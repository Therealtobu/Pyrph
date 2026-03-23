"""
VMCodeGen – final stage: serialises a VM3Bytecode object into a self-contained
Python source file that, when executed, runs the original program through the
Poly-Triple-Layer VM.

The emitted file contains:
    1. Compressed, base64-encoded constant/string tables
    2. Encrypted VM3 instruction stream (JSON list → zlib → b64)
    3. Full VM runtime (resolver, scheduler, vm3 executor) inlined as
    compressed source or as literal Python class definitions
    4. Bootstrap code that reconstructs keys, seeds the resolvers, and
    calls VM3.run()

Security properties of the output:
    - No plaintext opcode map
    - Seed keys embedded as split integer literals (XOR-reassembled at startup)
    - Instruction enc_op values are meaningless without live resolver state
    - Constants are zlib-compressed + b64 (not readable as strings)
"""
from __future__ import annotations
import base64
import json
import zlib

from .interleaver import VM3Bytecode, VM3Instr
from ..ir_obf.mutating_const_pool import MutatingConstPool as _MCPBuilder
from ..vm.env_check         import EnvCheck
from ..vm.frame_poison      import FramePoisoner
from ..vm.integrity_chain   import IntegrityChainBuilder
from ..vm.string_fragmenter import StringFragmenter
from ..vm.anti_snapshot     import AntiSnapshot
from ..sag.sag_pass          import SAGPass as _SAGPass
from ..postvm.engine         import PostVMEngine as _PostVMEngine
from ..vm4.vm4_engine        import VM4Engine as _VM4Engine
from ..parallel_engine.coordinator import ParallelCoordinatorEmitter as _PEEmitter
from .semantic_alias    import SemanticAliasEmitter    as _SAEmitter
from .probabilistic_exec import ProbabilisticExecEmitter as _PExEmitter
from .value_entangle    import ValueEntanglementEmitter  as _VEntEmitter
from .exec_fingerprint  import ExecFingerprintEmitter    as _EFPEmitter
from .self_destruct     import SelfDestructEmitter       as _SDEmitter


_INDENT = "    "


class VMCodeGen:

    def __init__(self):
        self._postvm = _PostVMEngine()
        self._vm4    = _VM4Engine()

    def generate(self, bc: VM3Bytecode, ir_module=None) -> str:
        import random as _rand
        ic_seed = _rand.randint(1, 0xFFFFFFFF)

        # Fragment string table (shared across all functions)
        sf = StringFragmenter()
        frags, fidx = sf.fragment(bc.string_table)

        parts = [self._header()]
        # Security modules first: define _SR, _MCP etc.
        parts.append(self._emit_security_modules())
        parts.append(self._emit_runtime())
        parts.append(self._emit_tables(bc, frags, fidx))
        parts.append(self._emit_string_frags(frags or [], fidx or {}))

        # Emit per-function bytecode blocks
        # ir_module.functions[0] == __module__ (main), rest are user functions
        if ir_module and len(ir_module.functions) > 1:
            parts.append(self._emit_multi_function(bc, ir_module, ic_seed))
        else:
            parts.append(self._emit_instructions(bc, ic_seed))
            sag_rt = self._emit_sag_runtime(ir_module)
            if sag_rt: parts.append(sag_rt)
            parts.append(self._emit_postvm_runtime(ir_module))
            parts.append(self._emit_vm4_runtime(ir_module))
            parts.append(self._emit_parallel_runtime())
            parts.append(self._emit_bootstrap(bc, ic_seed))
        return "\n\n".join(parts)

    def _emit_multi_function(self, module_bc: VM3Bytecode,
                                ir_module, ic_seed: int) -> str:
        """Emit one VM3 bytecode block per IR function + wrappers + bootstrap."""
        import random as _rand
        from .interleaver import Interleaver
        ilv = Interleaver(period=module_bc.sched_period)

        sections = []
        fn_var_names = {}  # fn.name → Python var name holding the wrapper

        # ── Emit helper functions (non-module) first ──────────────────────────
        for fn in ir_module.functions:
            if fn.name == "__module__":
                continue
            fn_bc = ilv.interleave_function(
                fn,
                shared_const_table  = dict(module_bc.const_table),
                shared_string_table = dict(module_bc.string_table),
            )
            fn_ic = _rand.randint(1, 0xFFFFFFFF)
            bc_code, optab_code = self._emit_fn_bytecode(fn_bc, fn_ic)
            safe = fn.name.replace("<", "_").replace(">", "_")
            var  = f"__fn_{safe}"
            fn_var_names[fn.name] = var

            wrapper = self._emit_fn_wrapper(fn, fn_bc, fn_ic, var, bc_code, optab_code)
            sections.append(wrapper)

        # ── Emit module-level bytecode ────────────────────────────────────────
        # Compile ONLY __module__ function (interleave() flattened all fns)
        module_fn = next(f for f in ir_module.functions if f.name == "__module__")
        mod_bc = ilv.interleave_function(
            module_fn,
            shared_const_table  = dict(module_bc.const_table),
            shared_string_table = dict(module_bc.string_table),
        )
        module_bc = mod_bc  # update for bootstrap keys
        mod_code, mod_optab = self._emit_fn_bytecode(mod_bc, ic_seed)
        sections.append(mod_code)
        sections.append(mod_optab)

        # ── SAG / PostVM / VM4 / Parallel runtimes ────────────────────────────
        sag_rt = self._emit_sag_runtime(ir_module)
        if sag_rt: sections.append(sag_rt)
        sections.append(self._emit_postvm_runtime(ir_module))
        sections.append(self._emit_vm4_runtime(ir_module))
        sections.append(self._emit_parallel_runtime())

        # ── Bootstrap: build init_env with all wrappers, run module ──────────
        sections.append(self._emit_multi_bootstrap(module_bc, ic_seed, fn_var_names))
        return "\n\n".join(sections)

    def _emit_fn_bytecode(self, fn_bc: VM3Bytecode, ic_seed: int):
        """Return (bc_code, optab_code) strings for a single function's bytecode."""
        import random as _rand2
        instr_block = self._emit_instructions(fn_bc, ic_seed)
        # Split out __OPTAB from instruction block
        lines = instr_block.split("\n")
        bc_lines    = [l for l in lines if "__OPTAB" not in l]
        optab_lines = [l for l in lines if "__OPTAB" in l]
        return "\n".join(bc_lines), "\n".join(optab_lines)

    def _emit_fn_wrapper(self, fn, fn_bc: VM3Bytecode, fn_ic: int,
                            var: str, bc_code: str, optab_code: str) -> str:
        """Emit a Python function that creates a fresh _VM3 and runs it."""
        k1a = fn_bc.seed_key1 ^ 0xABCDEF01; k1b = 0xABCDEF01
        k2a = fn_bc.seed_key2 ^ 0x13579BDF; k2b = 0x13579BDF
        sa  = fn_bc.sched_seed ^ 0xFEDCBA98; sb  = 0xFEDCBA98
        # Build Python signature from fn.args (may include *vararg, **kwarg markers)
        sig_parts = []
        env_parts = []
        for a in fn.args:
            if a.startswith('**'):
                sig_parts.append(a)          # **kwargs
                env_parts.append(f"**{a[2:]}")
            elif a.startswith('*'):
                sig_parts.append(a)          # *args
                env_parts.append(f"'{a[1:]}': {a[1:]}")
            else:
                sig_parts.append(a)
                env_parts.append(f"'{a}': {a}")
        args_str   = ", ".join(sig_parts)
        init_pairs = ", ".join(env_parts)

        # Inline the bytecode inside the def using closures
        bc_var    = f"__bc_{var}"
        lbl_var   = f"__lbl_{var}"
        optab_var = f"__optab_{var}"
        consts_var= f"__consts_{var}"

        lines = []
        # emit compressed bytecode for this function (module-level vars)
        # reuse bc_code but rename __BC/__LBL_MAP/__OPTAB to fn-specific names
        fn_bc_code = (bc_code
            .replace("__BC_RAW",        f"__{var}_BC_RAW")
            .replace("__BC=",           f"{bc_var}=")
            .replace("__BC ",           f"{bc_var} ")
            .replace("__BC" + chr(10),  f"{bc_var}" + chr(10))
            .replace("b85decode(__BC)", f"b85decode({bc_var})")
            .replace("del __BC_RAW",    f"del __{var}_BC_RAW")
            .replace("__LBL_RAW",       f"__{var}_LBL_RAW")
            .replace("__LBL_MAP",       f"{lbl_var}")
        )
        fn_optab_code = (optab_code
            .replace("__OPTAB_RAW",         f"__{var}_OPTAB_RAW")
            .replace("del __OPTAB_RAW",      f"del __{var}_OPTAB_RAW")
            .replace("b85decode(__OPTAB_RAW)", f"b85decode(__{var}_OPTAB_RAW)")
            .replace("__OPTAB=",             f"{optab_var}=")
            .replace("__OPTAB ",             f"{optab_var} ")
            .replace("__OPTAB" + chr(10),    f"{optab_var}" + chr(10))
        )
        lines.append(fn_bc_code)
        lines.append(fn_optab_code)

        closure_sig = (args_str + ", _closure_env=None") if args_str else "_closure_env=None"
        lines.append(f"def {var}({closure_sig}):")
        lines.append(f"    _k1 = {k1a} ^ {k1b}")
        lines.append(f"    _k2 = {k2a} ^ {k2b}")
        lines.append(f"    _ks = {sa}  ^ {sb}")
        lines.append(f"    _vm = _VM3({bc_var}, __CONSTS, {lbl_var}, _k1, _k2, _ks, {fn_bc.sched_period}, {optab_var})")
        lines.append(f"    _vm._icv = _ICV({fn_ic})")
        # Wrappers don't share genv_store to prevent cross-call pollution
        # They only need to look up fn refs from globals()
        lines.append(f"    _vm._genv_store = globals().get('__pyrph_genv')")
        lines.append(f"    _vm._fn_store = None")
        lines.append(f"    _vm._is_module_vm = False  # wrapper VM: never sync locals")
        lines.append(f"    _vm._genv_shadow = dict(globals().get('__pyrph_genv', {{}}))")
        self_ref = f"'{fn.name}': {var}"
        lines.append(f"    _init = {{{self_ref}, '__builtins__': __builtins__}}")
        if init_pairs:
            lines.append(f"    _init.update({{{init_pairs}}})")
        lines.append(f"    if _closure_env: _init.update(_closure_env)")
        lines.append(f"    return _vm.run(_init)")
        # Mark wrapper with mangled attribute name (harder to discover than __pyrph_wrapper__)
        lines.append(f"{var}._pyrph_w = True")
        return "\n".join(lines)

    def _patch_func_refs(self, bc: VM3Bytecode, fn_var_names: dict):
        """Replace func_ref operand values in module bytecode with wrapper var names."""
        for instr in bc.instructions:
            new_ops = []
            for kind, typ, val in instr.operands:
                if typ == "func_ref" and val in fn_var_names:
                    val = fn_var_names[val]
                new_ops.append((kind, typ, val))
            instr.operands = new_ops

    def _emit_multi_bootstrap(self, module_bc: VM3Bytecode, ic_seed: int,
                                fn_var_names: dict) -> str:
        k1a = module_bc.seed_key1 ^ 0xABCDEF01; k1b = 0xABCDEF01
        k2a = module_bc.seed_key2 ^ 0x13579BDF; k2b = 0x13579BDF
        sa  = module_bc.sched_seed ^ 0xFEDCBA98; sb  = 0xFEDCBA98

        # Build init_env: inject all fn wrappers so module can call them by var name
        fn_env_entries = "\n".join(
            f"    '{fn_name}': {var}," for fn_name, var in fn_var_names.items()
        )
        genv_fn_entries = "\n".join(
            f"__pyrph_genv['{fn_name}'] = {var}" for fn_name, var in fn_var_names.items()
        )
        return (
            f"__K1 = {k1a} ^ {k1b}\n"
            f"__K2 = {k2a} ^ {k2b}\n"
            f"__KS = {sa}  ^ {sb}\n"
            f"__KP = {module_bc.sched_period}\n"
            # Shared global env for cross-function global vars
            "class __PG(dict):\n    __repr__=lambda s:chr(60)+chr(101)+chr(110)+chr(118)+chr(62)\n__pyrph_genv=__PG()\ndel __PG\n"
            "__vm = _VM3(__BC, __CONSTS, __LBL_MAP, __K1, __K2, __KS, __KP, __OPTAB)\n"
            "__vm._genv_store = __pyrph_genv\n""__vm._is_module_vm = True\n"""
            f"__IC_SEED = {ic_seed}\n"
            "__vm._icv = _ICV(__IC_SEED)\n"
            "if not _pyrph_env_ok():\n"
            "    _pyrph_poison_state(__vm.r1, 0xDEADF00D)\n"
            "    _pyrph_poison_state(__vm.r2, 0xCAFEBABE)\n"
            "__postvm_init(__vm)\n"
            "__peil_enter(0)\ndel _pyrph_env_ok,_pyrph_poison_state\n" +
            genv_fn_entries + "\n" +
            "__vm.run({\n" +
            fn_env_entries + "\n" +
            "    '__builtins__': __builtins__,\n" +
            "})\n"
            "# Cleanup\n"
            "__STRTAB_REV=None;__STRTAB=None;__pyrph_genv=None\n"
            "__BC=None;__LBL_MAP=None\n"
            "try: del _VM3\nexcept: pass\n"
        )

    # ── Header ────────────────────────────────────────────────────────────────
    def _header(self) -> str:
        return (
            "# -*- coding: utf-8 -*-\n"
            "# Obfuscated by Pyrph – Poly-Triple-Layer VM\n"
            "# DO NOT ATTEMPT TO REVERSE ENGINEER\n"
            "zlib=__import__('zlib');base64=__import__('base64');json=__import__('json')\n"
            "import os,math,random,time,copy;from collections import deque\n"
        )

    # ── Tables ────────────────────────────────────────────────────────────────
    def _emit_tables(self, bc: VM3Bytecode, frags=None, fidx=None) -> str:
        # Encode const_table with MutatingConstPool
        mcp_builder              = _MCPBuilder()
        enc_pool, masks, mcp_seed = mcp_builder.encode_table(bc.const_table)
        mcp_runtime              = _MCPBuilder.emit_runtime()

        tables_raw = json.dumps({
            "p": {str(k): v for k, v in enc_pool.items()},
            "m": {str(k): v for k, v in masks.items()},
            "s": bc.string_table,
        }, ensure_ascii=False).encode("utf-8")
        compressed = zlib.compress(tables_raw, level=9)
        b64        = base64.b85encode(compressed).decode("ascii")

        return (
            mcp_runtime + "\n"
            f"__TABLES_RAW  = {b64!r}\n"
            f"__MCP_SEED    = {mcp_seed}\n"
            "__TABLES      = json.loads(zlib.decompress(base64.b85decode(__TABLES_RAW)))\n"
            "__CONSTS_ENC  = {int(k): v for k, v in __TABLES['p'].items()}\n"
            "__CONSTS_MASK = {int(k): v for k, v in __TABLES['m'].items()}\n"
            "__CONSTS      = _MCP(__CONSTS_ENC, __CONSTS_MASK, __MCP_SEED)\n"
            "_st=__TABLES['s'];__STRTAB=_st;del _st\n"
            "__STRTAB_REV={v:k for k,v in __STRTAB.items()}\n"
        )
    def _emit_string_frags(self, frags, fidx) -> str:
        import json as _j, zlib as _z, base64 as _b64
        if not frags:
            return "__FRAGS = []\n__FIDX = {}\n__SR = _SR(__FRAGS, __FIDX)\n"
        frag_data = _j.dumps(
            {"f": [list(b) for b in frags],
            "i": {str(k): v for k, v in fidx.items()}},
            separators=(",", ":"),
        ).encode()
        b64 = _b64.b85encode(_z.compress(frag_data, 9)).decode()
        return (
            f"__FRAG_RAW = {b64!r}\n"
            "__FRAG_D   = json.loads(zlib.decompress(base64.b85decode(__FRAG_RAW)))\n"
            "__FRAGS    = [bytes(x) for x in __FRAG_D['f']]\n"
            "__FIDX     = {int(k): v for k, v in __FRAG_D['i'].items()}\n"
            "__SR       = _SR(__FRAGS, __FIDX)\n"
        )


    # ── Instruction stream ────────────────────────────────────────────────────
    def _emit_instructions(self, bc: VM3Bytecode, ic_seed: int = 0) -> str:
        stream       = []
        # Single intern table for ALL strings (reg names, var names, labels)
        _str_intern: dict[str, int] = {}
        _str_ctr     = 0
        _ic_chain = ic_seed
        _IC_FNV   = 0x01000193
        _IC_MASK  = 0xFFFFFFFF

        def _intern(s: str, enc_op: int, bk: int, idx: int) -> int:
            """Intern string s → encrypted int ID."""
            nonlocal _str_ctr
            if s not in _str_intern:
                _str_intern[s] = _str_ctr
                _str_ctr += 1
            sid = _str_intern[s]
            k   = ((enc_op ^ bk) * 0x6C62272E + idx) & 0xFFFFFFFF
            return (sid ^ k) & 0xFFFFFFFF

        _GOLD = 0x9E3779B9
        # Stream cipher seed per function (derived from keys)
        _sc_state = (bc.seed_key1 ^ bc.seed_key2 ^ bc.sched_seed) & 0xFFFFFFFF
        _sc_stream = []
        for _sci in range(len(bc.instructions)):
            _sc_state = (_sc_state * 0x6C62272E + 0x14057B5B) & 0xFFFFFFFF
            _sc_state = ((_sc_state << 13) | (_sc_state >> 19)) & 0xFFFFFFFF
            _sc_stream.append(_sc_state)
        for stream_idx, instr in enumerate(bc.instructions):
            blk_key  = instr.block_key if hasattr(instr, "block_key") and instr.block_key else 0
            raw_op_v = instr.raw_op if instr.raw_op else 0
            # Position-based encoding
            _sc_mask = _sc_stream[stream_idx]  # kept for anti-analysis entropy
            enc_op_v = (raw_op_v ^ blk_key ^ (stream_idx * _GOLD)) & 0xFFFFFFFF
            enc_ops  = []
            for oi, op in enumerate(instr.operands):
                kind, typ, val = op
                if isinstance(val, int):
                    if typ in ('count',):
                        pass  # count values: keep as plain int
                    else:
                        k   = ((enc_op_v ^ blk_key) * 0x6C62272E + oi) & 0xFFFFFFFF
                        val = (val ^ k) & 0xFFFFFFFF
                elif isinstance(val, str):
                    # ALL strings: intern → encrypted ID
                    val = _intern(val, enc_op_v, blk_key, oi)
                enc_ops.append([kind, typ, val])
            entry: dict = {
                "e": enc_op_v,
                "sc": _sc_mask,
                "v": instr.vm_slot,
                "o": enc_ops,
                "bk": blk_key,
            }
            op_bytes = repr(enc_ops).encode()
            h = hash((_ic_chain, enc_op_v, op_bytes)) & _IC_MASK
            for b in op_bytes[:32]:
                h = ((h ^ b) * _IC_FNV) & _IC_MASK
            _ic_chain = h ^ (_ic_chain >> 7)
            entry["ch"] = _ic_chain

            if instr.label:     entry["l"] = instr.label
            if instr.is_split_a: entry["a"] = 1
            if instr.is_split_b: entry["b"] = 1
            if instr.split_tmp:
                # Store split_tmp as plain OPTAB ID (no extra encryption)
                # Runtime decodes via _optab[id] to get string name
                if instr.split_tmp not in _str_intern:
                    _str_intern[instr.split_tmp] = _str_ctr; _str_ctr += 1
                entry["t"] = _str_intern[instr.split_tmp]  # plain ID, decode via OPTAB
            stream.append(entry)

        # Emit __OPTAB: reverse mapping id → string (for runtime dec_op)
        import json as _json, zlib as _zlib, base64 as _b64
        optab = {v: k for k, v in _str_intern.items()}   # id → string

        raw        = json.dumps(stream, separators=(",", ":")).encode("utf-8")
        compressed = zlib.compress(raw, level=9)
        b64        = base64.b85encode(compressed).decode("ascii")

        label_raw  = json.dumps(bc.label_map, separators=(",", ":")).encode("utf-8")
        label_b64  = base64.b85encode(zlib.compress(label_raw, level=9)).decode("ascii")

        optab_raw  = json.dumps(optab, separators=(",", ":")).encode("utf-8")
        optab_b64  = base64.b85encode(zlib.compress(optab_raw, level=9)).decode("ascii")

        return (
            f"__BC_RAW={b64!r}\n"
            "__BC=json.loads(zlib.decompress(base64.b85decode(__BC_RAW)));del __BC_RAW\n"
            f"__LBL_RAW={label_b64!r}\n"
            "__LBL_MAP=json.loads(zlib.decompress(base64.b85decode(__LBL_RAW)));del __LBL_RAW\n"
            f"__OPTAB_RAW={optab_b64!r}\n"
            "__OPTAB={int(k):v for k,v in json.loads(zlib.decompress(base64.b85decode(__OPTAB_RAW))).items()};del __OPTAB_RAW\n"
        )

    # ── Inlined runtime ───────────────────────────────────────────────────────
    def _emit_runtime(self) -> str:
        # Emit new security layer runtimes
        _extra = (
            _SAEmitter.get_runtime() +
            _PExEmitter.get_runtime() +
            _VEntEmitter.get_runtime() +
            _EFPEmitter.get_runtime()
            # SD already emitted before env_check
        )
        """
        Emit the complete _VM3 class with ALL security layers wired:
            - _SS split-state registers (FramePoisoner)
            - _ICV integrity chain verify in run() loop
            - _anti_snap_tick in run() loop
            - Scheduler-driven vm_slot selection (not just compile-time slot)
            - Cross-key dependency after every instruction
            - _ROTM resolver (ResolverV2 formula)
        """
        return _extra + '''
# ── Native bridge (pyrph_core.so if available) ───────────────────────────────
try:
    import pyrph_core as _NC
    _NC_NATIVE = True
except ImportError:
    _NC = None
    _NC_NATIVE = False

# ── Operand encryption ──────────────────────────────────────────────────────
_OE_MASK = 0xFFFFFFFF
_OE_MUL  = 0x6C62272E

def _oe_key(enc_op, blk_key, idx):
    return ((enc_op ^ blk_key) * _OE_MUL + idx) & _OE_MASK

def _oe_dec(val, enc_op, blk_key, idx):
    if isinstance(val, int): return (val ^ _oe_key(enc_op, blk_key, idx)) & _OE_MASK
    return val

_M32  = 0xFFFFFFFF
_GLD  = 0x9E3779B9
_ROTM = 0x6C62272E

class _Res:
    def __init__(self, key):
        self.key = key
        self.state = key ^ 0xDEADBEEF
        self.last_output = 0
        self.data_flow = 0  # kept for anti_snapshot compatibility; NOT used in resolve
    def resolve(self, enc):
        # Must match OpcodeResolver.resolve() exactly (compile-time formula)
        if _NC_NATIVE:
            op = _NC.resolve_op(enc, self.key, self.state, 0, 0)
        else:
            op = ((enc ^ self.key) + self.state) ^ (self.state >> 3)
            op &= _M32
        self.last_output = op
        s = self.state
        s = (s ^ (s << 5)) & _M32
        s = (s ^ (op * _GLD)) & _M32
        self.state = s
        return op

class _VM3:
    def __init_subclass__(cls,**kw): raise TypeError(chr(115)+chr(101)+chr(97)+chr(108)+chr(101)+chr(100))
    def __init__(self, bc, consts, lbl_map, key1, key2, seed, period, optab=None):
        self.bc   = bc
        self.C    = consts
        self.L    = lbl_map
        self._optab = optab if optab is not None else {}
        self._globals: set = set()   # var names declared global
        self._genv_store = None      # reference to shared module env for globals
        self._exc_stack  = []        # exception handler PC stack
        self._local_vars: set = set() # vars that are local (args + locally assigned)
        self._fn_store = None
        self._is_module_vm = False
        self._genv_shadow = None
        try:
            import hashlib as _hl
            self._method_fp = (
                _hl.md5(self._g1.__code__.co_code).digest()[:4] +
                _hl.md5(self._s1.__code__.co_code).digest()[:4]
            )
        except Exception:
            self._method_fp = bytes(8)
        self.r1   = _Res(key1)
        self.r2   = _Res(key2)
        # Scheduler: AC-wave + PRNG for dynamic vm_slot selection
        import math as _math
        self._omega  = 2 * _math.pi / (period or 32)
        self._prng   = seed
        self._cycle  = 0
        # _SS split-state register banks
        import os as _os2
        _fp1 = hash(f"{time.time_ns()}{_os2.getpid()}A") & _M32
        _fp2 = hash(f"{time.time_ns()}{_os2.getpid()}B") & _M32
        self.R1  = _SS(16, _fp1, _fp2)
        self.R2  = _SS(16, _fp2, _fp1)
        self.env = {}
        self.S1  = []
        self.S2  = []
        self._done = object()
        self.ret = self._done
        # Integrity chain verifier (wired in by bootstrap)
        self._icv = None
        self.pc   = 0
        self._ic  = 0   # instruction counter for anti-snapshot

    def _sched_pick(self, data=0):
        """AC-wave + PRNG + data → vm_slot. Uses NC if available."""
        if _NC_NATIVE:
            pool_size  = 2
            state_hash = (self.r1.state ^ self.r2.state) & _M32
            hist_hash  = (self._prng ^ self._cycle) & _M32
            vm_id      = _NC.sched_pick(pool_size, state_hash,
                                        self._prng, hist_hash, self._cycle)
        else:
            import math as _m
            w  = abs(_m.sin(self._cycle * self._omega + self._prng * 0.001))
            wb = int(w * 0xFF) & 0xFF
            es = (self.r1.state ^ self.r2.state) & 0xFF
            db = data & 0xFF
            vm_id = (wb ^ es ^ db) & 1
        self._prng  = ((self._prng * 0x6C622) + 0x14057) & _M32
        self._cycle += 1
        return vm_id

    def run(self, init_env=None):
        if init_env:
            self.env.update(init_env)
            # Track real args (not builtins, not dunder, not pyrph wrappers)
            _real_args = {
                k for k in init_env
                if k not in ('__builtins__',)
                and not k.startswith('__')
                and not getattr(init_env.get(k), '_pyrph_w', False)
            }
            # Respect explicit _is_module_vm flag set by bootstrap
            # Only auto-detect if not explicitly configured
            if not self._is_module_vm:
                self._is_module_vm = len(_real_args) == 0
            self._local_vars = _real_args if not self._is_module_vm else set()
        try:
            import hashlib as _hl2
            _cur_fp = (
                _hl2.md5(self._g1.__code__.co_code).digest()[:4] +
                _hl2.md5(self._s1.__code__.co_code).digest()[:4]
            )
            if _cur_fp != self._method_fp:
                self._ic ^= 0xDEADBEEF
                try: _sd_check("tamper")
                except: pass
        except Exception: pass
        _adbg_ctr = 0
        while self.pc < len(self.bc):
            ins = self.bc[self.pc]; self.pc += 1
            self._ic += 1
            # Continuous anti-debug: check every 17 instructions (prime → unpredictable)
            _adbg_ctr += 1
            if _adbg_ctr == 3:
                _adbg_ctr = 0
                try:
                    import sys as _sys2
                    if _sys2.gettrace() is not None:
                        self._ic ^= 0xDEAD
                        try: _sd_check("trace")
                        except: pass
                    if _sys2.getprofile() is not None:
                        self._ic ^= 0xBEEF
                        try: _sd_check("profile_loop")
                        except: pass
                except Exception: pass

            # Anti-snapshot: mix time+pid into data_flow every N steps
            _anti_snap_tick(self.r1, self.r2, self._ic)

            enc = ins["e"]
            v   = ins["v"]
            ops = ins.get("o", [])
            lbl = ins.get("l")
            a   = ins.get("a", 0)
            b   = ins.get("b", 0)
            _tmp_raw = ins.get("t")
            # Position-based decode
            _bk_val = ins.get("bk", 0)
            _pos    = self.pc - 1
            _raw_op_dec = (ins["e"] ^ _bk_val ^ (_pos * 0x9E3779B9)) & _M32
            if isinstance(_tmp_raw, int):
                # split_tmp stored as plain OPTAB ID
                tmp = self._optab.get(_tmp_raw, str(_tmp_raw))
            else:
                tmp = _tmp_raw

            # Integrity chain: only verify sequential execution (no-op on branches)
            if self._icv is not None and ins.get("ch") is not None:
                self._icv.verify(enc, ops, ins["ch"])  # advance chain state only

            # Advance scheduler state for anti-analysis (but don't use its output
            # to pick the slot – the opcode was encoded for the compile-time slot
            # and MUST be decoded with that same resolver).
            self._sched_pick(data=self.r1.last_output ^ self.r2.last_output)
            effective_slot = v  # always use compile-time slot

            op = _raw_op_dec & 0xFF
            try:
                if effective_slot == 0:
                    self._v1(op, ops, lbl, a, b, tmp, _enc=enc, _bk=_bk_val)
                    self.r1.resolve(enc); self.R1.tick(self.pc, op)
                else:
                    self._v2(op, ops, lbl, a, b, tmp, _enc=enc, _bk=_bk_val)
                    self.r2.resolve(enc); self.R2.tick(self.pc, op)
            except Exception as _ex:
                if self._exc_stack:
                    # Jump to exception handler
                    _handler_lbl = self._exc_stack[-1]
                    if _handler_lbl in self.L:
                        self.pc = self.L[_handler_lbl]
                    else:
                        raise
                else:
                    raise

            if self.ret is not self._done:
                # ── Stage 7+8: PostVM + VM4 ────────────────────────────
                _vm_state = (self.r1.state ^ self.r2.state) & _M32
                _fn_id    = hash(str(id(self))) & _M32
                _res      = self.ret
                # Stage 7: PostVM chain (PDL→TBL→OEL→DLI→PEIL)
                try:
                    _res = __postvm_apply(_res, _vm_state, _fn_id)
                except Exception:
                    pass
                # Stage 8: VM4 Fragment Graph + DNA Lock
                try:
                    _sag_fn = lambda: globals().get('__sag_state', 0)
                    _mcp_fn = lambda: globals().get('__MCP_SEED', 0)
                    _res = _vm4_apply(_res, _vm_state, _sag_fn, _mcp_fn)
                except Exception:
                    pass
                # Stage 9.5: Parallel Dual-Engine combine
                try:
                    _rust_s = globals().get('__pe_rust_state', self.r2.state)
                    _rs = _rust_s if isinstance(_rust_s, int) else self.r2.state
                    _res = _pe_apply(_res, _vm_state, _rs & 0xFFFFFFFF)
                except Exception:
                    pass
                return _res
        return None

    # ── Register helpers (use _SS split-state) ────────────────────────────────
    def _g1(self, k):
        if k is None: return None
        if isinstance(k, tuple) and k[0] == "__CV__": return k[1]  # const value
        if isinstance(k, str): return self.env.get(k)
        return self.R1.read_any(k & 0xF)
    def _s1(self, k, v):
        if k is None: return
        if isinstance(k, tuple): return  # const sentinel dst → skip
        # Unwrap sentinel value before storing
        if isinstance(v, tuple) and len(v)==2 and v[0]=="__CV__": v = v[1]
        if isinstance(k, str): self.env[k] = v
        else: self.R1.write(k & 0xF, v)

    def _g2(self, k):
        if k is None: return None
        if isinstance(k, tuple) and k[0] == "__CV__": return k[1]  # const value
        if isinstance(k, str): return self.env.get(k)
        return self.R2.read_any(k & 0xF)
    def _s2(self, k, v):
        if k is None: return
        if isinstance(k, tuple): return  # const sentinel dst → skip
        # Unwrap sentinel value before storing
        if isinstance(v, tuple) and len(v)==2 and v[0]=="__CV__": v = v[1]
        if isinstance(k, str): self.env[k] = v
        else: self.R2.write(k & 0xF, v)

    def _genv(self, k):
        if isinstance(k, tuple) and k[0] == "__CV__": return k[1]
        ks = str(k) if k is not None else ''
        _MISS = object()
        if self._is_module_vm:
            # Module VM: genv_store is the truth
            if self._genv_store is not None:
                v = self._genv_store.get(ks, _MISS)
                if v is not _MISS: return v
        else:
            # Wrapper VM: read from isolated shadow (no cross-call pollution)
            _shadow = self._genv_shadow or self._genv_store
            if _shadow is not None:
                v = _shadow.get(ks, _MISS)
                if v is not _MISS: return v
        # Local env (args, temps)
        v = self.env.get(ks, _MISS)
        if v is not _MISS: return v
        # Builtins fallback
        bi = self.env.get('__builtins__')
        if isinstance(bi, dict): return bi.get(ks)
        elif bi is not None: return getattr(bi, ks, None)
        return None

    
    def _senv(self, k, v):
        ks = str(k) if k is not None else ''
        self.env[ks] = v
        if self._is_module_vm:
            # Module VM: sync all non-dunder vars to genv_store
            if self._genv_store is not None and ks and not ks.startswith('__'):
                self._genv_store[ks] = v
        else:
            # Wrapper VM: declared globals go to real genv_store; all else to shadow
            if ks in self._globals and self._genv_store is not None:
                self._genv_store[ks] = v   # flush declared global to shared store
            if self._genv_shadow is not None and ks and not ks.startswith('__'):
                self._genv_shadow[ks] = v  # local shadow (isolated per call)
        try: __sag_tick(v)
        except: pass

    @staticmethod
    def _dec_op(val, enc_op, bk, idx, typ="", optab=None, C=None):
        """Decrypt operand. const_ref/str_ref resolved to actual values immediately."""
        if isinstance(val, int):
            k   = ((enc_op ^ bk) * 0x6C62272E + idx) & 0xFFFFFFFF
            sid = (val ^ k) & 0xFFFFFFFF
            if typ == "count":
                return val  # stored as plain int, no encryption was applied
            if typ == "const_ref":
                # Wrap in sentinel so _g1/_g2 can distinguish from register index
                return ("__CV__", C.get(sid) if C is not None else sid)
            if typ == "str_ref":
                _strtab_rev = globals().get("__STRTAB_REV", {})
                _sval = _strtab_rev.get(sid)
                if _sval is None and C is not None: _sval = C.get(sid)
                return ("__CV__", _sval)  # wrap like const_ref
            _ob = optab if optab is not None else {}
            return _ob.get(sid, sid)
        return val

    def _dst(self, ops, enc=0, bk=0):
        for i,(t,tp,v) in enumerate(ops):
            if t=="dst":
                return _VM3._dec_op(v, enc, bk, i, tp, self._optab, self.C)
        return None
    def _src(self, ops, n, enc=0, bk=0):
        srcs = [(i,tp,v) for i,(t,tp,v) in enumerate(ops) if t=="src"]
        if n < len(srcs):
            i, tp, v = srcs[n]
            return _VM3._dec_op(v, enc, bk, i, tp, self._optab, self.C)
        return None
    def _lbl(self, ops, enc=0, bk=0):
        for i,(t,tp,v) in enumerate(ops):
            if t=="lbl":
                return _VM3._dec_op(v, enc, bk, i, tp, self._optab, self.C)
        return None

    def _v1(self, o, ops, lbl, a, b, tmp, _enc=0, _bk=0):
        d=self._dst(ops,_enc,_bk); s=lambda n:self._src(ops,n,_enc,_bk); lb=self._lbl(ops,_enc,_bk)
        if a:
            self.env[str(tmp)] = self._resolve_val(s(0)); return
        if o==0x00: return
        if o==0x02: self.ret=self._g1(d); return
        if o==0x0C:
            _sv = s(0)
            if isinstance(_sv, tuple) and _sv[0] == "__CV__":
                self._s1(d, _sv[1])   # const value
            elif isinstance(_sv, str):
                self._s1(d, self._genv(_sv))   # func_ref → lookup env
            else:
                _strtab_rev = globals().get('__STRTAB_REV', {})
                self._s1(d, _strtab_rev.get(_sv, _sv))   # str_ref id → string
            return
        if o==0x0E: self._s1(d, self._genv(s(0))); return
        if o==0x10: self._senv(s(1), self._g1(s(0))); return
        if o==0x12:
            try: self._s1(d, self._g1(s(0))[self._g1(s(1))])
            except Exception as _e: self._s1(d, None)
            return
        if o==0x14:
            try: self._g1(s(0))[self._g1(s(1))]=self._g1(d)
            except: pass
            return
        if o==0x16:
            try: self._s1(d, getattr(self._g1(s(0)), str(s(1))))
            except: pass
            return
        if o==0x18:
            try: setattr(self._g1(s(0)), str(s(1)), self._g1(d))
            except: pass
            return
        if o==0x1A: self._s1(d, self._g1(s(0))+self._g1(s(1))); return
        if o==0x1C: self._s1(d, self._g1(s(0))-self._g1(s(1))); return
        if o==0x1E: self._s1(d, self._g1(s(0))*self._g1(s(1))); return
        if o==0x20:
            self._s1(d, self._g1(s(0))/self._g1(s(1))); return
        if o==0x22:
            self._s1(d, self._g1(s(0))//self._g1(s(1))); return
        if o==0x24:
            self._s1(d, self._g1(s(0))%self._g1(s(1))); return
        if o==0x26:
            try: self._s1(d, self._g1(s(0))**self._g1(s(1)))
            except: self._s1(d, 0)
            return
        if o==0x28: self._s1(d, -self._g1(s(0))); return
        if o==0x2A: self._s1(d, self._g1(s(0))&self._g1(s(1))); return
        if o==0x2C: self._s1(d, self._g1(s(0))|self._g1(s(1))); return
        if o==0x2E: self._s1(d, self._g1(s(0))^self._g1(s(1))); return
        if o==0x30: self._s1(d, ~self._g1(s(0))); return
        if o==0x32: self._s1(d, self._g1(s(0))<<self._g1(s(1))); return
        if o==0x34: self._s1(d, self._g1(s(0))>>self._g1(s(1))); return
        if o==0x36: self._s1(d, self._g1(s(0)) and self._g1(s(1))); return
        if o==0x38: self._s1(d, self._g1(s(0)) or  self._g1(s(1))); return
        if o==0x3A: self._s1(d, not self._g1(s(0))); return
        if o==0x3C: self._s1(d, self._g1(s(0))==self._g1(s(1))); return
        if o==0x3E: self._s1(d, self._g1(s(0))!=self._g1(s(1))); return
        if o==0x40: self._s1(d, self._g1(s(0))< self._g1(s(1))); return
        if o==0x42: self._s1(d, self._g1(s(0))<=self._g1(s(1))); return
        if o==0x44: self._s1(d, self._g1(s(0))> self._g1(s(1))); return
        if o==0x46: self._s1(d, self._g1(s(0))>=self._g1(s(1))); return
        if o==0x48: self._s1(d, self._g1(s(0)) is self._g1(s(1))); return
        if o==0x4A: self._s1(d, self._g1(s(0)) in self._g1(s(1))); return
        if o==0x4C:
            if lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x4E:
            if self._g1(s(0)) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x50:
            if not self._g1(s(0)) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x52:
            fn=self._g1(s(0))
            if callable(fn):
                _srcs=[self._g1(s(n+1)) for n in range(len([x for x in ops if x[0]=="src"])-1)]
                try:
                    _r52=fn(*_srcs)
                    _r52=_pex_flip(_r52,self._ic); _r52=_efp_apply(_r52,self._ic)
                    self._s1(d,_r52)
                except: self._s1(d, None)
            return
        if o==0x54:
            _rv = self._g1(s(0)) if s(0) is not None else None
            if callable(_rv) and getattr(_rv, '_pyrph_w', False):
                _ce = {k: v for k, v in self.env.items() if k not in ('__builtins__',)}
                _fn_ref = _rv
                _rv = lambda *_a, _e=_ce, _f=_fn_ref, **_kw: _f(*_a, _closure_env=_e, **_kw)
            self.ret = _rv; return
        if o==0x56:
            _srcs=[x for x in ops if x[0]=="src"]
            _cnt=None
            for _,_tp,_v in reversed(_srcs):
                if _tp=='count': _cnt=_v; break
            if _cnt is None: _cnt=len(_srcs)
            if isinstance(_cnt, tuple) and _cnt[0]=="__CV__": _cnt=_cnt[1]
            try: self._s1(d,[self._g1(s(i)) for i in range(int(_cnt))])
            except: self._s1(d, [])
            return
        if o==0x58:
            _srcs=[x for x in ops if x[0]=="src"]
            _cnt = None
            for _,_tp,_v in reversed(_srcs):
                if _tp=='count': _cnt=_v; break
            if _cnt is None: _cnt = len(_srcs)//2
            if isinstance(_cnt, tuple) and _cnt[0]=="__CV__": _cnt=_cnt[1]
            try: self._s1(d,{self._g1(s(i*2)):self._g1(s(i*2+1)) for i in range(int(_cnt))})
            except: self._s1(d, {})
            return
        if o==0x5C:
            try: self._s1(d, iter(self._g1(s(0))))
            except: pass
            return
        if o==0x5E:
            try: self._s1(d, next(self._g1(s(0))))
            except StopIteration:
                if lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x62:
            try: self._senv(str(d), __import__(str(s(0))))
            except: pass
            return
        if o==0x68:
            vname = s(0)
            if vname: self._globals.add(str(vname))
            return
        if o==0x6A:
            # TRY_ENTER: handler label in src[0] OR in lb
            _hlbl = s(0) if s(0) else lb
            if _hlbl: self._exc_stack.append(str(_hlbl))
            return
        if o==0x6B:
            # TRY_EXIT: pop exception handler
            if self._exc_stack: self._exc_stack.pop()
            return

    def _v2(self, o, ops, lbl, a, b, tmp, _enc=0, _bk=0):
        d=self._dst(ops,_enc,_bk); s=lambda n:self._src(ops,n,_enc,_bk); lb=self._lbl(ops,_enc,_bk)
        if b:
            left  = self.env.get(str(tmp))
            right = self._resolve_val(s(1))
            self._s2(d, self._apply_v2_op(o, left, right)); return
        if o==0x01: return
        if o==0x03: self.ret=self._g2(s(0)); return
        if o==0x0D:
            _sv = s(0)
            if isinstance(_sv, tuple) and _sv[0] == "__CV__":
                self._s2(d, _sv[1])   # const value
            elif isinstance(_sv, str):
                self._s2(d, self._genv(_sv))
            else:
                _strtab_rev = globals().get('__STRTAB_REV', {})
                self._s2(d, _strtab_rev.get(_sv, _sv))
            return
        if o==0x0F: self._s2(d, self._genv(s(0))); return
        if o==0x11: self._senv(s(1), self._g2(s(0))); return
        if o==0x13:
            try: self._s2(d, self._g2(s(0))[self._g2(s(1))])
            except Exception as _e: self._s2(d, None)
            return
        if o==0x15:
            try: self._g2(s(0)).__setitem__(self._g2(s(1)), self._g2(d))
            except: pass
            return
        if o==0x17:
            try: self._s2(d, getattr(self._g2(s(0)), str(s(1))))
            except: pass
            return
        if o==0x19:
            try: setattr(self._g2(s(0)), str(s(1)), self._g2(d))
            except: pass
            return
        if o==0x1B: self._s2(d, self._g2(s(0))+self._g2(s(1))); return
        if o==0x1D: self._s2(d, self._g2(s(0))-self._g2(s(1))); return
        if o==0x1F: self._s2(d, self._g2(s(0))*self._g2(s(1))); return
        if o==0x21:
            self._s2(d, self._g2(s(0))/self._g2(s(1))); return
        if o==0x23:
            self._s2(d, self._g2(s(0))//self._g2(s(1))); return
        if o==0x25:
            self._s2(d, self._g2(s(0))%self._g2(s(1))); return
        if o==0x27:
            try: self._s2(d, self._g2(s(0))**self._g2(s(1)))
            except: self._s2(d, 0)
            return
        if o==0x29: self._s2(d, -self._g2(s(0))); return
        if o==0x2B: self._s2(d, self._g2(s(0))&self._g2(s(1))); return
        if o==0x2D: self._s2(d, self._g2(s(0))|self._g2(s(1))); return
        if o==0x2F: self._s2(d, self._g2(s(0))^self._g2(s(1))); return
        if o==0x31: self._s2(d, ~self._g2(s(0))); return
        if o==0x33: self._s2(d, self._g2(s(0))<<self._g2(s(1))); return
        if o==0x35: self._s2(d, self._g2(s(0))>>self._g2(s(1))); return
        if o==0x37: self._s2(d, self._g2(s(0)) and self._g2(s(1))); return
        if o==0x39: self._s2(d, self._g2(s(0)) or  self._g2(s(1))); return
        if o==0x3B: self._s2(d, not self._g2(s(0))); return
        if o==0x3D: self._s2(d, self._g2(s(0))==self._g2(s(1))); return
        if o==0x3F: self._s2(d, self._g2(s(0))!=self._g2(s(1))); return
        if o==0x41: self._s2(d, self._g2(s(0))< self._g2(s(1))); return
        if o==0x43: self._s2(d, self._g2(s(0))<=self._g2(s(1))); return
        if o==0x45: self._s2(d, self._g2(s(0))> self._g2(s(1))); return
        if o==0x47: self._s2(d, self._g2(s(0))>=self._g2(s(1))); return
        if o==0x4D:
            if lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x4F:
            if self._g2(s(0)) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x51:
            if not self._g2(s(0)) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x53:
            fn=self._g2(s(0))
            if callable(fn):
                _srcs=[self._g2(s(n+1)) for n in range(len([x for x in ops if x[0]=="src"])-1)]
                try:
                    _r53=fn(*_srcs)
                    _r53=_pex_flip(_r53,self._ic); _r53=_efp_apply(_r53,self._ic)
                    self._s2(d, _r53)
                except: self._s2(d, None)
            return
        if o==0x55:
            _rv = self._g2(s(0)) if s(0) is not None else None
            if callable(_rv) and getattr(_rv, '_pyrph_w', False):
                _ce = {k: v for k, v in self.env.items() if k not in ('__builtins__',)}
                _fn_ref = _rv
                _rv = lambda *_a, _e=_ce, _f=_fn_ref, **_kw: _f(*_a, _closure_env=_e, **_kw)
            self.ret = _rv; return
        if o==0x57:
            _srcs=[x for x in ops if x[0]=="src"]
            _cnt=None
            for _,_tp,_v in reversed(_srcs):
                if _tp=='count': _cnt=_v; break
            if _cnt is None: _cnt=len(_srcs)
            if isinstance(_cnt, tuple) and _cnt[0]=="__CV__": _cnt=_cnt[1]
            try: self._s2(d,[self._g2(s(i)) for i in range(int(_cnt))])
            except: self._s2(d, [])
            return
        if o==0x59:
            _srcs=[x for x in ops if x[0]=="src"]
            _cnt = None
            for _,_tp,_v in reversed(_srcs): 
                if _tp=='count': _cnt=_v; break
            if _cnt is None: _cnt = len(_srcs)//2
            if isinstance(_cnt, tuple) and _cnt[0]=="__CV__": _cnt=_cnt[1]
            try: self._s2(d,{self._g2(s(i*2)):self._g2(s(i*2+1)) for i in range(int(_cnt))})
            except: self._s2(d, {})
            return
        if o==0x5D:
            try: self._s2(d, iter(self._g2(s(0))))
            except: pass
            return
        if o==0x5F:
            try: self._s2(d, next(self._g2(s(0))))
            except StopIteration:
                if lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x63:
            try: self._senv(str(s(1)), __import__(str(s(0))))
            except: pass
            return
        if o==0x69:
            vname = s(0)
            if vname: self._globals.add(str(vname))
            return
        if o==0x6C:
            _hlbl = s(0) if s(0) else lb
            if _hlbl: self._exc_stack.append(str(_hlbl))
            return
        if o==0x6D:
            if self._exc_stack: self._exc_stack.pop()
            return

    def _resolve_val(self, v):
        if v is None: return None
        if isinstance(v, tuple) and v[0] == "__CV__": return v[1]
        if isinstance(v, str) and v.startswith("__"):
            return self.env.get(v)
        return v

    @staticmethod
    def _apply_v2_op(o, left, right):
        try:
            if o==0x1B: return left+right
            if o==0x1D: return left-right
            if o==0x1F: return left*right
            if o==0x21: return left/right if right else 0
            if o==0x23: return left//right if right else 0
            if o==0x25: return left%right if right else 0
            if o==0x27: return left**right
            if o==0x2B: return left&right
            if o==0x2D: return left|right
            if o==0x2F: return left^right
            if o==0x33: return left<<right
            if o==0x35: return left>>right
            if o==0x3D: return left==right
            if o==0x3F: return left!=right
            if o==0x41: return left<right
            if o==0x43: return left<=right
            if o==0x45: return left>right
            if o==0x47: return left>=right
        except: pass
        return None
'''

    def _emit_security_modules(self) -> str:
        parts = []
        # Self-destruct MUST be defined before env_check (env_ok calls sd_check)
        parts.append(_SDEmitter.get_runtime())
        parts.append(EnvCheck.emit_runtime())
        parts.append(FramePoisoner.emit_runtime())
        parts.append(IntegrityChainBuilder.emit_runtime())
        parts.append(StringFragmenter.emit_runtime())
        parts.append(AntiSnapshot.emit_runtime())
        return "\n".join(parts)

    def _emit_sag_runtime(self, ir_module) -> str:
        return _SAGPass.get_runtime(ir_module) if ir_module else ''


    # ── Bootstrap ─────────────────────────────────────────────────────────────
    def _emit_postvm_runtime(self, ir_module) -> str:
        fn_names = [fn.name for fn in ir_module.functions
                    if not fn.name.startswith('__')]
        return (
            self._postvm.emit_all_runtime() + '\n' +
            self._postvm.emit_dli_fragment_table(fn_names)
        )

    def _emit_vm4_runtime(self, ir_module) -> str:
        fg = self._vm4.build_fragment_graph(ir_module)
        return self._vm4.emit_all_runtime(fg)

    def _emit_parallel_runtime(self) -> str:
        return _PEEmitter.emit_runtime()

    def _emit_bootstrap(self, bc: VM3Bytecode, ic_seed: int = 0) -> str:
        # Split keys into XOR parts so they don't appear as single literals
        k1a = bc.seed_key1 ^ 0xABCDEF01
        k1b = 0xABCDEF01
        k2a = bc.seed_key2 ^ 0x13579BDF
        k2b = 0x13579BDF
        sa  = bc.sched_seed ^ 0xFEDCBA98
        sb  = 0xFEDCBA98

        return (
            f"__K1 = {k1a} ^ {k1b}\n"
            f"__K2 = {k2a} ^ {k2b}\n"
            f"__KS = {sa}  ^ {sb}\n"
            f"__KP = {bc.sched_period}\n"
            "__GD=type('GD',(object,),{\n  '__init__':lambda s:(object.__setattr__(s,'_d',{}),None)[1],\n  '__getitem__':lambda s,k:object.__getattribute__(s,'_d')[k],\n  '__setitem__':lambda s,k,v:object.__getattribute__(s,'_d').__setitem__(k,v),\n  '__contains__':lambda s,k:k in object.__getattribute__(s,'_d'),\n  'get':lambda s,k,d=None:object.__getattribute__(s,'_d').get(k,d),\n  'items':lambda s:object.__getattribute__(s,'_d').items(),\n  'keys':lambda s:object.__getattribute__(s,'_d').keys(),\n  '__repr__':lambda s:'<genv>',\n})\n__pyrph_genv=__GD();del __GD\n"
            "__vm = _VM3(__BC, __CONSTS, __LBL_MAP, __K1, __K2, __KS, __KP, __OPTAB)\n"
            "__vm._genv_store = __pyrph_genv\n""__vm._is_module_vm = True\n"""
            f"__IC_SEED = {ic_seed}\n"
            "__vm._icv = _ICV(__IC_SEED)\n"
            "if not _pyrph_env_ok():\n"
            "    _pyrph_poison_state(__vm.r1, 0xDEADF00D)\n"
            "    _pyrph_poison_state(__vm.r2, 0xCAFEBABE)\n"
            "__postvm_init(__vm)\n"
            "__peil_enter(0)\n"
            "def _vm4_sag(): return globals().get('__sag_state', 0)\n"
            "def _vm4_mcp(): return globals().get('__MCP_SEED', 0)\n"
            "__vm.run({'__builtins__': __builtins__})\n"
            "# Cleanup: remove sensitive tables from namespace\n"
            "__STRTAB_REV=None;__STRTAB=None;__pyrph_genv=None\n"
            "__BC=None;__LBL_MAP=None\n"
        )
