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
from ir_obf.mutating_const_pool import MutatingConstPool as _MCPBuilder
from vm.env_check         import EnvCheck
from vm.frame_poison      import FramePoisoner
from vm.integrity_chain   import IntegrityChainBuilder
from vm.string_fragmenter import StringFragmenter
from vm.anti_snapshot     import AntiSnapshot
from sag.sag_pass          import SAGPass as _SAGPass
from postvm.engine         import PostVMEngine as _PostVMEngine
from vm4.vm4_engine        import VM4Engine as _VM4Engine


_INDENT = "    "


class VMCodeGen:

    def __init__(self):
        self._postvm = _PostVMEngine()
        self._vm4    = _VM4Engine()

    def generate(self, bc: VM3Bytecode, ir_module=None) -> str:
        # Build integrity chain before serialising instructions
        ic_builder = IntegrityChainBuilder()
        bc.instructions, ic_seed = ic_builder.build(bc.instructions)

        # Fragment string table
        sf = StringFragmenter()
        frags, fidx = sf.fragment(bc.string_table)

        parts = [self._header()]
        parts.append(self._emit_tables(bc, frags, fidx))
        parts.append(self._emit_string_frags(frags or [], fidx or {}))
        parts.append(self._emit_instructions(bc, ic_seed))
        parts.append(self._emit_runtime())
        parts.append(self._emit_security_modules())
        sag_rt = self._emit_sag_runtime(ir_module)
        if sag_rt: parts.append(sag_rt)
        parts.append(self._emit_postvm_runtime(ir_module))
        parts.append(self._emit_vm4_runtime(ir_module))
        parts.append(self._emit_bootstrap(bc, ic_seed))
        return "\n\n".join(parts)

    # ── Header ────────────────────────────────────────────────────────────────
    def _header(self) -> str:
        return (
            "# -*- coding: utf-8 -*-\n"
            "# Obfuscated by Pyrph – Poly-Triple-Layer VM\n"
            "# DO NOT ATTEMPT TO REVERSE ENGINEER\n"
            "import os, math, random, time, zlib, base64, json, copy\n"
            "from collections import deque\n"
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
            "__STRTAB      = __TABLES['s']\n"
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
        stream = []
        for instr in bc.instructions:
            meta  = getattr(instr, "meta", {})
            entry: dict = {
                "e": instr.enc_op,
                "v": instr.vm_slot,
                "o": instr.operands,
            }
            if meta.get("ch") is not None:
                entry["ch"] = meta["ch"]
            if instr.label:     entry["l"] = instr.label
            if instr.is_split_a: entry["a"] = 1
            if instr.is_split_b: entry["b"] = 1
            if instr.split_tmp:  entry["t"] = instr.split_tmp
            stream.append(entry)

        raw        = json.dumps(stream, separators=(",", ":")).encode("utf-8")
        compressed = zlib.compress(raw, level=9)
        b64        = base64.b85encode(compressed).decode("ascii")

        label_raw  = json.dumps(bc.label_map, separators=(",", ":")).encode("utf-8")
        label_b64  = base64.b85encode(zlib.compress(label_raw, level=9)).decode("ascii")

        return (
            f"__BC_RAW   = {b64!r}\n"
            "__BC        = json.loads(zlib.decompress(base64.b85decode(__BC_RAW)))\n"
            f"__LBL_RAW  = {label_b64!r}\n"
            "__LBL_MAP   = json.loads(zlib.decompress(base64.b85decode(__LBL_RAW)))\n"
        )

    # ── Inlined runtime ───────────────────────────────────────────────────────
    def _emit_runtime(self) -> str:
        """
        Emit the complete _VM3 class with ALL security layers wired:
          - _SS split-state registers (FramePoisoner)
          - _ICV integrity chain verify in run() loop
          - _anti_snap_tick in run() loop
          - Scheduler-driven vm_slot selection (not just compile-time slot)
          - Cross-key dependency after every instruction
          - _ROTM resolver (ResolverV2 formula)
        """
        return '''
_M32  = 0xFFFFFFFF
_GLD  = 0x9E3779B9
_ROTM = 0x6C62272E

class _Res:
    def __init__(self, key):
        self.key = key
        self.state = key ^ 0xDEADBEEF
        self.last_output = 0
        self.prev_op   = 0
        self.data_flow = 0
    def resolve(self, enc):
        base    = ((enc ^ self.key) + self.state) ^ (self.state >> 3)
        base   &= _M32
        rotated = (base ^ (self.prev_op * _ROTM)) & _M32
        op      = (rotated + self.data_flow) ^ ((self.data_flow << 7) & _M32)
        op     &= _M32
        self.last_output = op
        self.prev_op     = op
        s = self.state
        s = (s ^ (s << 5)) & _M32
        s = (s ^ (op * _GLD)) & _M32
        self.state = s
        return op
    def encode(self, real_op):
        rotated = ((real_op ^ ((self.data_flow << 7) & _M32)) - self.data_flow) & _M32
        base    = (rotated ^ (self.prev_op * _ROTM)) & _M32
        inner   = (base ^ (self.state >> 3)) - self.state
        return (inner ^ self.key) & _M32
    def feed(self, v):
        m = v if isinstance(v, int) else hash(str(v)) & _M32
        self.data_flow = (self.data_flow ^ m) & _M32

class _VM3:
    def __init__(self, bc, consts, lbl_map, key1, key2, seed, period):
        self.bc   = bc
        self.C    = consts
        self.L    = lbl_map
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
        """AC-wave + PRNG + data → vm_slot. Runtime dynamic, not compile-time."""
        import math as _m
        w  = abs(_m.sin(self._cycle * self._omega + self._prng * 0.001))
        wb = int(w * 0xFF) & 0xFF
        es = (self.r1.state ^ self.r2.state) & 0xFF
        db = data & 0xFF
        vm_id = (wb ^ es ^ db) & 1
        self._prng = ((self._prng * 0x6C622) + 0x14057) & _M32
        self._cycle += 1
        return vm_id

    def run(self, init_env=None):
        if init_env:
            self.env.update(init_env)
        while self.pc < len(self.bc):
            ins = self.bc[self.pc]; self.pc += 1
            self._ic += 1

            # Anti-snapshot: mix time+pid into data_flow every N steps
            _anti_snap_tick(self.r1, self.r2, self._ic)

            enc = ins["e"]
            v   = ins["v"]
            ops = ins.get("o", [])
            lbl = ins.get("l")
            a   = ins.get("a", 0)
            b   = ins.get("b", 0)
            tmp = ins.get("t")

            # Integrity chain verify BEFORE decode
            if self._icv is not None and ins.get("ch") is not None:
                if not self._icv.verify(enc, ops, ins["ch"]):
                    # Silent corruption – do not crash
                    self.r1.key = (self.r1.key ^ 0xBADC0FFE) & _M32
                    self.r2.key = (self.r2.key ^ 0xDEADC0DE) & _M32

            # Runtime dynamic slot selection (overrides compile-time slot)
            # Uses compile-time slot as tiebreak when scheduler agrees
            rt_slot = self._sched_pick(data=self.r1.last_output ^ self.r2.last_output)
            # Blend: if compile-time and runtime agree → use it; else XOR
            effective_slot = (v ^ rt_slot ^ (self.r1.state & 1)) & 1

            if effective_slot == 0:
                op = self.r1.resolve(enc)
                self._v1(op & 0xFF, ops, lbl, a, b, tmp)
                # Cross-key: after VM1 → update VM2 key
                self.r2.key = hash(self.r1.last_output) & _M32
                # Feed result into data_flow for next resolver
                self.r1.feed(self.r1.last_output)
                # Tick _SS re-key
                self.R1.tick(self.pc, op)
            else:
                op = self.r2.resolve(enc)
                self._v2(op & 0xFF, ops, lbl, a, b, tmp)
                # Cross-key: after VM2 → update VM1 key
                self.r1.key = hash(self.r2.state) & _M32
                self.r2.feed(self.r2.last_output)
                self.R2.tick(self.pc, op)

            if self.ret is not self._done:
                return self.ret
        return None

    # ── Register helpers (use _SS split-state) ────────────────────────────────
    def _g1(self, k):
        if k is None: return None
        if isinstance(k, int): return self.R1.read_any(k & 0xF)
        return self.env.get(str(k))
    def _s1(self, k, v):
        if k is None: return
        if isinstance(k, int): self.R1.write(k & 0xF, v)
        else:
            self.env[str(k)] = v
            if hasattr(self, "__sag_tick"): pass  # SAG tick handled separately

    def _g2(self, k):
        if k is None: return None
        if isinstance(k, int): return self.R2.read_any(k & 0xF)
        return self.env.get(str(k))
    def _s2(self, k, v):
        if k is None: return
        if isinstance(k, int): self.R2.write(k & 0xF, v)
        else: self.env[str(k)] = v

    def _genv(self, k): return self.env.get(str(k))
    def _senv(self, k, v):
        self.env[str(k)] = v
        # SAG observer effect: writing to env mutates SAG state
        try: __sag_tick(v)
        except: pass

    @staticmethod
    def _dst(ops):
        for t,tp,v in ops:
            if t=="dst": return v
        return None
    @staticmethod
    def _src(ops, n):
        s=[v for t,tp,v in ops if t=="src"]
        return s[n] if n<len(s) else None
    @staticmethod
    def _lbl(ops):
        for t,tp,v in ops:
            if t=="lbl": return v
        return None

    def _v1(self, o, ops, lbl, a, b, tmp):
        d=self._dst(ops); s=lambda n:self._src(ops,n); lb=self._lbl(ops)
        if a:
            self.env[str(tmp)] = self._resolve_val(s(0)); return
        if o==0x00: return
        if o==0x02: self.ret=self._g1(d); return
        if o==0x0C: self._s1(d, self.C.get(s(0)) if hasattr(self.C,'get') else self.C[s(0)] if s(0) in self.C else None); return
        if o==0x0E: self._s1(d, self._genv(s(0))); return
        if o==0x10: self._senv(s(1), self._g1(d)); return
        if o==0x12:
            try: self._s1(d, self._g1(s(0))[self._g1(s(1))])
            except: pass
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
            _b=self._g1(s(1))
            self._s1(d, self._g1(s(0))/_b if _b else 0); return
        if o==0x22:
            _b=self._g1(s(1))
            self._s1(d, self._g1(s(0))//_b if _b else 0); return
        if o==0x24:
            _b=self._g1(s(1))
            self._s1(d, self._g1(s(0))%_b if _b else 0); return
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
            if self._g1(d) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x50:
            if not self._g1(d) and lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x52:
            fn=self._g1(d)
            if callable(fn):
                _srcs=[self._g1(s(n)) for n in range(len([x for x in ops if x[0]=="src"]))]
                try: self._s1(d, fn(*_srcs))
                except: self._s1(d, None)
            return
        if o==0x54:
            self.ret = self._g1(d) if d is not None else None; return
        if o==0x56:
            n=s(0) or 0
            try: self._s1(d,[self._g1(s(i+1)) for i in range(int(n))])
            except: self._s1(d, [])
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

    def _v2(self, o, ops, lbl, a, b, tmp):
        d=self._dst(ops); s=lambda n:self._src(ops,n); lb=self._lbl(ops)
        if b:
            left  = self.env.get(str(tmp))
            right = self._resolve_val(s(1))
            self._s2(d, self._apply_v2_op(o, left, right)); return
        if o==0x01: return
        if o==0x03: self.ret=self._g2(0); return
        if o==0x0D: self._s2(s(1), self.C.get(s(0)) if hasattr(self.C,'get') else None); return
        if o==0x0F: self._s2(s(1), self._genv(s(0))); return
        if o==0x11: self._senv(str(s(1)), self._g2(s(0))); return
        if o==0x13:
            try: self._s2(s(2), self._g2(s(0))[self._g2(s(1))])
            except: pass
            return
        if o==0x1B: self._s2(s(2), self._g2(s(0))+self._g2(s(1))); return
        if o==0x1D: self._s2(s(2), self._g2(s(0))-self._g2(s(1))); return
        if o==0x1F: self._s2(s(2), self._g2(s(0))*self._g2(s(1))); return
        if o==0x21:
            _b=self._g2(s(1))
            self._s2(s(2), self._g2(s(0))/_b if _b else 0); return
        if o==0x23:
            _b=self._g2(s(1))
            self._s2(s(2), self._g2(s(0))//_b if _b else 0); return
        if o==0x25:
            _b=self._g2(s(1))
            self._s2(s(2), self._g2(s(0))%_b if _b else 0); return
        if o==0x27:
            try: self._s2(s(2), self._g2(s(0))**self._g2(s(1)))
            except: self._s2(s(2), 0)
            return
        if o==0x29: self._s2(s(1), -self._g2(s(0))); return
        if o==0x2B: self._s2(s(2), self._g2(s(0))&self._g2(s(1))); return
        if o==0x2D: self._s2(s(2), self._g2(s(0))|self._g2(s(1))); return
        if o==0x2F: self._s2(s(2), self._g2(s(0))^self._g2(s(1))); return
        if o==0x31: self._s2(s(1), ~self._g2(s(0))); return
        if o==0x33: self._s2(s(2), self._g2(s(0))<<self._g2(s(1))); return
        if o==0x35: self._s2(s(2), self._g2(s(0))>>self._g2(s(1))); return
        if o==0x37: self._s2(s(2), self._g2(s(0)) and self._g2(s(1))); return
        if o==0x39: self._s2(s(2), self._g2(s(0)) or  self._g2(s(1))); return
        if o==0x3B: self._s2(s(1), not self._g2(s(0))); return
        if o==0x3D: self._s2(s(2), self._g2(s(0))==self._g2(s(1))); return
        if o==0x3F: self._s2(s(2), self._g2(s(0))!=self._g2(s(1))); return
        if o==0x41: self._s2(s(2), self._g2(s(0))< self._g2(s(1))); return
        if o==0x43: self._s2(s(2), self._g2(s(0))<=self._g2(s(1))); return
        if o==0x45: self._s2(s(2), self._g2(s(0))> self._g2(s(1))); return
        if o==0x47: self._s2(s(2), self._g2(s(0))>=self._g2(s(1))); return
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
                try: self._s2(s(0), fn(*_srcs))
                except: self._s2(s(0), None)
            return
        if o==0x55:
            self.ret = self._g2(s(0)) if s(0) is not None else None; return
        if o==0x5D:
            try: self._s2(s(1), iter(self._g2(s(0))))
            except: pass
            return
        if o==0x5F:
            try: self._s2(s(1), next(self._g2(s(0))))
            except StopIteration:
                if lb and lb in self.L: self.pc=self.L[lb]
            return
        if o==0x63:
            try: self._senv(str(s(1)), __import__(str(s(0))))
            except: pass
            return

    def _resolve_val(self, v):
        if v is None: return None
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
            "__vm = _VM3(__BC, __CONSTS, __LBL_MAP, __K1, __K2, __KS, __KP)\n"
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
        )
