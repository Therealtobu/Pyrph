"""
vm/poly_vm_gen.py
==================
Generate a pure-Python polymorphic VM interpreter.

Used when:
  a) No C compiler is available (native pack fallback)
  b) The user explicitly requests --vm-only mode

The generated VM is different on every run:
  - All internal variable names are randomly generated
  - Opcode byte values are shuffled (per OpcodeMap)
  - Dispatch cases are shuffled in random order
  - Fake (dead) handler cases are injected as noise
  - Constant pool entries are XOR-encrypted
  - Bytecode itself is XOR+perm encrypted

This means two runs of the same source produce completely different
Python VM code that cannot be pattern-matched.

The output is a self-contained .py file that includes:
  1. Encrypted constant pool header
  2. Encrypted bytecode blob
  3. Polymorphic VM function (unique variable names + shuffled dispatch)
  4. Entry call
"""
from __future__ import annotations
import random
import string
from .opcodes import OpcodeMap, Bytecode, ALL_OPCODES
from .encryptor import encrypt_bytecode


# ── Name generator ────────────────────────────────────────────────────────

def _rn(n: int = 6) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0, n-1)
    return "_" + raw[:pos] + random.choice(letters) + raw[pos:]


class _Names:
    """Unique random names for all VM internals."""
    def __init__(self):
        used = set()
        def f(n=6):
            while True:
                v = _rn(n)
                if v not in used:
                    used.add(v); return v
        self.stk    = f()
        self.ip     = f()
        self.bc     = f()
        self.op     = f()
        self.arg    = f()
        self.frame  = f()
        self.globs  = f()
        self.regs   = f()
        self.run    = f(8)
        self.consts = f()
        self.names  = f()
        self.reg_keys = [f() for _ in range(8)]


# ── Constant pool encryption ──────────────────────────────────────────────

def _encrypt_const_pool(constants: list, rng: random.Random) -> tuple:
    """
    XOR-encrypt string/bytes constants in the pool.
    Returns (encrypted_pool, key_map) where key_map[i] = key for constants[i].
    """
    pool = []
    keys = {}
    for i, c in enumerate(constants):
        if isinstance(c, str):
            raw  = c.encode("utf-8")
            key  = [rng.randint(1, 254) for _ in raw]
            enc  = bytes(b ^ k for b, k in zip(raw, key))
            pool.append(("str", enc, key))
            keys[i] = key
        elif isinstance(c, bytes):
            key  = [rng.randint(1, 254) for _ in c]
            enc  = bytes(b ^ k for b, k in zip(c, key))
            pool.append(("bytes", enc, key))
            keys[i] = key
        else:
            pool.append(("raw", c, None))
    return pool, keys


# ── Bytecode encryption ───────────────────────────────────────────────────

def _encrypt_bc(bc_bytes: bytes, rng: random.Random) -> tuple:
    """
    XOR-encrypt bytecode with a random key.
    Returns (enc_bytes, key, step).
    """
    key_len = rng.randint(16, 32)
    key     = [rng.randint(1, 254) for _ in range(key_len)]
    step    = rng.choice([1, 3, 5, 7])
    enc     = bytearray(bc_bytes)
    ki      = 0
    for i in range(len(enc)):
        enc[i] ^= key[ki]; ki = (ki + step) % key_len
    return bytes(enc), key, step


# ── Handler code generation ───────────────────────────────────────────────

def _build_handlers(n: _Names, om: OpcodeMap) -> list:
    """Return list of (opcode_byte, handler_code_str) for each opcode."""
    S = n.stk; IP = n.ip; BC = n.bc; O = n.op; A = n.arg
    F = n.frame; G = n.globs; R = n.regs; C = n.consts; N = n.names

    def _push(val): return f"{S}.append({val})"
    def _pop():     return f"{S}.pop()"
    def _peek():    return f"{S}[-1]"

    handlers = []

    def add(opname: str, code: str):
        handlers.append((om[opname], opname, code))

    # Stack
    add("LOAD_CONST",   f"{A}={BC}[{IP}];{IP}+=1;{_push(f'{C}[{A}]')}")
    add("LOAD_NAME",    f"{A}={BC}[{IP}];{IP}+=1;_k={N}[{A}];"
                        f"_v={F}.get(_k) or {G}.get(_k) or getattr(__import__('builtins'),_k,None);"
                        f"{_push('_v')}")
    add("STORE_NAME",   f"{A}={BC}[{IP}];{IP}+=1;{F}[{N}[{A}]]={_pop()}")
    add("DEL_NAME",     f"{A}={BC}[{IP}];{IP}+=1;{F}.pop({N}[{A}],None)")
    add("POP",          f"{_pop()}")
    add("DUP",          f"{_push(f'{_peek()}')}")
    add("ROT2",         f"_a={_pop()};_b={_pop()};{_push('_a')};{_push('_b')}")
    add("ROT3",         f"_a={_pop()};_b={_pop()};_c={_pop()};{_push('_a')};{_push('_c')};{_push('_b')}")

    # Registers
    add("REG_LOAD",     f"{A}={BC}[{IP}];{IP}+=1;{_push(f'{R}[{A}&7]')}")
    add("REG_STORE",    f"{A}={BC}[{IP}];{IP}+=1;{R}[{A}&7]={_pop()}")

    # Arithmetic
    add("ADD",          f"_b={_pop()};_a={_pop()};{_push('_a+_b')}")
    add("SUB",          f"_b={_pop()};_a={_pop()};{_push('_a-_b')}")
    add("MUL",          f"_b={_pop()};_a={_pop()};{_push('_a*_b')}")
    add("DIV",          f"_b={_pop()};_a={_pop()};{_push('_a/_b')}")
    add("FLOORDIV",     f"_b={_pop()};_a={_pop()};{_push('_a//_b')}")
    add("MOD",          f"_b={_pop()};_a={_pop()};{_push('_a%_b')}")
    add("POW",          f"_b={_pop()};_a={_pop()};{_push('_a**_b')}")
    add("NEG",          f"{_push(f'-{_pop()}')}")
    add("POS",          f"{_push(f'+{_pop()}')}")

    # Bitwise
    add("BAND",         f"_b={_pop()};_a={_pop()};{_push('_a&_b')}")
    add("BOR",          f"_b={_pop()};_a={_pop()};{_push('_a|_b')}")
    add("BXOR",         f"_b={_pop()};_a={_pop()};{_push('_a^_b')}")
    add("BINV",         f"{_push(f'~{_pop()}')}")
    add("BSHL",         f"_b={_pop()};_a={_pop()};{_push('_a<<_b')}")
    add("BSHR",         f"_b={_pop()};_a={_pop()};{_push('_a>>_b')}")

    # Compare
    add("CMP_EQ",       f"_b={_pop()};_a={_pop()};{_push('_a==_b')}")
    add("CMP_NE",       f"_b={_pop()};_a={_pop()};{_push('_a!=_b')}")
    add("CMP_LT",       f"_b={_pop()};_a={_pop()};{_push('_a<_b')}")
    add("CMP_LE",       f"_b={_pop()};_a={_pop()};{_push('_a<=_b')}")
    add("CMP_GT",       f"_b={_pop()};_a={_pop()};{_push('_a>_b')}")
    add("CMP_GE",       f"_b={_pop()};_a={_pop()};{_push('_a>=_b')}")
    add("CMP_IN",       f"_b={_pop()};_a={_pop()};{_push('_a in _b')}")
    add("CMP_NOT_IN",   f"_b={_pop()};_a={_pop()};{_push('_a not in _b')}")
    add("CMP_IS",       f"_b={_pop()};_a={_pop()};{_push('_a is _b')}")
    add("CMP_IS_NOT",   f"_b={_pop()};_a={_pop()};{_push('_a is not _b')}")
    add("NOT",          f"{_push(f'not {_pop()}')}")

    # Jumps (2-byte big-endian target)
    add("JMP",          f"_a=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}=_a")
    add("JMP_TRUE",     f"_a=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}+=2;_v={S}.pop();"
                        f"_a2=_a if _v else {IP};{IP}=_a2")
    add("JMP_FALSE",    f"_a=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}+=2;_v={S}.pop();"
                        f"_a2=_a if not _v else {IP};{IP}=_a2")
    add("JMP_TRUE_PEEK",  f"_a=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}+=2;"
                          f"_a2=_a if ({S}[-1] if {S} else None) else {IP};{IP}=_a2")
    add("JMP_FALSE_PEEK", f"_a=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}+=2;"
                          f"_a2=_a if not ({S}[-1] if {S} else None) else {IP};{IP}=_a2")

    # Function
    add("MAKE_FUNC",    f"{A}={BC}[{IP}];{IP}+=1;{_push(f'{C}[{A}]')}")
    add("CALL",         f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_args=list(reversed([{_pop()} for _ in range({A})]));_fn={_pop()};"
                        f"{_push('_fn(*_args)')}")
    add("RETURN",       f"return {_pop()}")

    # Attribute / item
    add("GET_ATTR",     f"{A}={BC}[{IP}];{IP}+=1;_o={_pop()};{_push(f'getattr(_o,{N}[{A}])')}")
    add("SET_ATTR",     f"{A}={BC}[{IP}];{IP}+=1;_v={_pop()};_o={_pop()};setattr(_o,{N}[{A}],_v)")
    add("GET_ITEM",     f"_k={_pop()};_o={_pop()};{_push('_o[_k]')}")
    add("SET_ITEM",     f"_v={_pop()};_k={_pop()};_o={_pop()};_o[_k]=_v")

    # Builders
    add("BUILD_LIST",   f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_ls=list(reversed([{_pop()} for _ in range({A})]));{_push('_ls')}")
    add("BUILD_TUPLE",  f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_ls=list(reversed([{_pop()} for _ in range({A})]));{_push('tuple(_ls)')}")
    add("BUILD_DICT",   f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_d={{}};_items=[({_pop()},{_pop()}) for _ in range({A})];"
                        f"[_d.__setitem__(_k,_v) for _k,_v in reversed(_items)];{_push('_d')}")
    add("BUILD_SET",    f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_ls=[{_pop()} for _ in range({A})];{_push('set(_ls)')}")
    add("BUILD_STR",    f"{A}={BC}[{IP}];{IP}+=1;"
                        f"_ls=list(reversed([str({_pop()}) for _ in range({A})]));{_push('\"\".join(_ls)')}")

    # Iteration
    add("GET_ITER",     f"{_push(f'iter({_pop()})')}")
    add("FOR_ITER",     f"{A}=({BC}[{IP}]<<8)|{BC}[{IP}+1];{IP}+=2;\n"
                        f"        try:_v=next({_peek()});{_push('_v')}\n"
                        f"        except StopIteration:{_pop()};{IP}={A}")
    add("UNPACK",       f"{A}={BC}[{IP}];{IP}+=1;_seq=list({_pop()});"
                        f"[{_push('_seq[_i]')} for _i in range({A})]")

    # Import
    add("IMPORT",       f"{A}={BC}[{IP}];{IP}+=1;{_push(f'__import__({N}[{A}])')}")
    add("IMPORT_FROM",  f"_mi={BC}[{IP}];_ai={BC}[{IP}+1];{IP}+=2;"
                        f"_m=__import__({N}[_mi]);{_push(f'getattr(_m,{N}[_ai])')}")

    # Exception
    add("RAISE",        f"raise {_pop()}")
    add("FORMAT_VAL",   f"{_push(f'str({_pop()})')}")
    add("HALT",         f"break")

    return handlers


# ── VM code generator ─────────────────────────────────────────────────────

def generate_vm(bc: Bytecode, seed: int = None) -> str:
    """
    Generate a self-contained polymorphic Python VM that executes `bc`.

    Returns a complete Python source string.
    """
    rng  = random.Random(seed)
    n    = _Names()
    om   = bc.opcode_map

    # Encrypt bytecode
    enc_bc, bc_key, bc_step = _encrypt_bc(bc.instructions, rng)

    # Encrypt constant pool
    const_pool, const_keys = _encrypt_const_pool(bc.constants, rng)

    # Build handlers and shuffle order
    handlers = _build_handlers(n, om)
    real_handlers = list(handlers)
    rng.shuffle(real_handlers)

    # Inject fake dead handlers (junk opcode bytes that never appear in real bytecode)
    used_bytes = {b for b,_,_ in handlers}
    free_bytes = [b for b in range(256) if b not in used_bytes]
    rng.shuffle(free_bytes)
    n_fake = min(12, len(free_bytes))
    for fb in free_bytes[:n_fake]:
        real_handlers.insert(rng.randint(0, len(real_handlers)),
                             (fb, f"FAKE_{fb}", "pass"))
    rng.shuffle(real_handlers)

    # ── Constant pool initialisation code ─────────────────────────────────
    lines = ["import base64 as _b64"]

    pool_var = _rn()
    lines.append(f"{pool_var}=[None]*{len(const_pool)}")
    for i, (typ, val, key) in enumerate(const_pool):
        if typ == "str" and key:
            kv = _rn()
            lines.append(f"{kv}={key!r}")
            lines.append(
                f"{pool_var}[{i}]=bytes(_x^{kv}[_j%len({kv})] "
                f"for _j,_x in enumerate({val!r})).decode('utf-8',errors='replace')"
            )
        elif typ == "bytes" and key:
            kv = _rn()
            lines.append(f"{kv}={key!r}")
            lines.append(
                f"{pool_var}[{i}]=bytes(_x^{kv}[_j%len({kv})] "
                f"for _j,_x in enumerate({val!r}))"
            )
        else:
            lines.append(f"{pool_var}[{i}]={val!r}")

    # ── Bytecode decrypt ───────────────────────────────────────────────────
    bc_var  = _rn(); bck_var = _rn(); bcs_var = _rn()
    lines += [
        f"{bck_var}={bc_key!r}",
        f"{bcs_var}={bc_step!r}",
        f"_enc={enc_bc!r}",
        f"_ki=0",
        f"_dec=bytearray(_enc)",
        f"for _i in range(len(_dec)):",
        f"    _dec[_i]^={bck_var}[_ki];_ki=(_ki+{bcs_var})%len({bck_var})",
        f"{bc_var}=bytes(_dec)",
    ]

    # ── Names pool ─────────────────────────────────────────────────────────
    nm_var = _rn()
    lines.append(f"{nm_var}={bc.names!r}")

    # ── VM function ────────────────────────────────────────────────────────
    regs_init = "{" + ",".join(f"{i!r}:None" for i in range(8)) + "}"
    lines += [
        f"def {n.run}({n.globs}=None):",
        f"    {n.globs}={n.globs} if {n.globs} is not None else "
        f"(dict(__builtins__) if isinstance(__builtins__,dict) "
        f"else {{k:getattr(__builtins__,k) for k in dir(__builtins__)}})",
        f"    {n.globs}['__name__']=__name__",
        f"    {n.frame}={{}}",
        f"    {n.stk}=[]",
        f"    {n.regs}={regs_init}",
        f"    {n.ip}=0",
        f"    {n.bc}={bc_var}",
        f"    {n.consts}={pool_var}",
        f"    {n.names}={nm_var}",
        f"    while {n.ip}<len({n.bc}):",
        f"        {n.op}={n.bc}[{n.ip}];{n.ip}+=1",
    ]

    # Build if/elif dispatch (shuffled)
    first = True
    for (byte_val, opname, handler_code) in real_handlers:
        keyword = "        if" if first else "        elif"
        first   = False
        # indent handler code
        handler_indented = "\n".join(
            "            " + l for l in handler_code.splitlines()
        )
        lines.append(f"{keyword} {n.op}=={byte_val}:  # {opname}")
        lines.append(handler_indented)

    lines += [
        f"    if {n.stk}:",
        f"        return {n.stk}[-1]",
        f"    return None",
        f"{n.run}()",
    ]

    return "\n".join(lines) + "\n"
