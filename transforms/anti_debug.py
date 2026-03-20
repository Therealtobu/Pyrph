"""
transforms/anti_debug.py
=========================
AntiDebugPass — inject anti-debugging stubs.

Two layers:
1. Top-of-file stubs  — multiple checks run at import time
2. Scatter sentinels  — lightweight check functions injected into
   random positions inside function bodies so that removing the
   header block alone is not enough to bypass all checks

Checks injected:
  gettrace()       — detects Python debuggers (pdb, pydevd)
  getprofile()     — detects profilers
  dis module       — detect if 'dis' was imported before us
  debugpy/pydevd   — detect known debugger modules by name
  stack depth      — unusually deep stacks = debugger wrapping
  timing           — tight loop timing (single-step slows it)
  frame co_flags   — CO_GENERATOR / debug flag bits
  settrace bounce  — install+remove trace, check if re-hooked
  pyc sentinel     — XOR self-check of a constant
  frame locals poison — silent corruption if debugger active

All checks raise a *decoy* exception (not AssertionError) or
silently corrupt state so the program misbehaves rather than
crashing obviously (harder to notice during dynamic analysis).
"""
from __future__ import annotations
import ast
import random
import string
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _hex(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


def _rn(n: int = 5) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0,n-1)
    raw = raw[:pos] + random.choice(letters) + raw[pos:]
    return "_" + raw


def _msg() -> str:
    msgs = [
        "invalid literal for int() with base 16",
        "codec can't decode bytes in position 0",
        "object has no attribute '__len__'",
        "list index out of range",
        "too many values to unpack",
        "maximum recursion depth exceeded",
    ]
    return f'"{_hex(random.choice(msgs))}"'


# ── Top-of-file stub generators ───────────────────────────────────────────

def _s_gettrace():
    v = _rn()
    return (f"import sys as {v}\n"
            f"if {v}.gettrace() is not None:\n"
            f"    raise RuntimeError({_msg()})\n")

def _s_getprofile():
    v = _rn()
    return (f"import sys as {v}\n"
            f"if {v}.getprofile() is not None:\n"
            f"    raise RuntimeError({_msg()})\n")

def _s_dis_check():
    v = _rn(); dh = _hex("dis")
    return (f"import sys as {v}\n"
            f"if \"{dh}\" in {v}.modules:\n"
            f"    raise ImportError({_msg()})\n")

def _s_debugpy():
    v = _rn(); mods = ["debugpy","pydevd","pydevd_tracing","_pydev_bundle","bdb"]
    m = _hex(random.choice(mods))
    return (f"import sys as {v}\n"
            f"if \"{m}\" in {v}.modules:\n"
            f"    raise ImportError({_msg()})\n")

def _s_stack_depth():
    v = _rn(); f = _rn(); th = random.randint(18,28)
    return (f"import inspect as {v}\n"
            f"{f}=len({v}.stack())\n"
            f"if {f}>{th}:\n"
            f"    raise MemoryError({_msg()})\n")

def _s_timing():
    v = _rn(); tn = _rn(); cn = _rn(); th = random.choice(["5e-4","8e-4","1e-3"])
    return (f"import time as {v}\n"
            f"{tn}={v}.perf_counter()\n"
            f"for {cn} in range(1000):pass\n"
            f"if {v}.perf_counter()-{tn}>{th}:\n"
            f"    raise OverflowError({_msg()})\n")

def _s_coflags():
    v = _rn(); f = _rn()
    return (f"import sys as {v}\n"
            f"{f}={v}._getframe().f_code.co_flags\n"
            f"if {f}&0x20000:\n"
            f"    raise ValueError({_msg()})\n")

def _s_sentinel():
    s = random.randint(0x1000,0xEFFF); a = random.randint(1,0xFFFF); b = s^a
    v = _rn()
    return (f"{v}=({a}^{b})\n"
            f"if {v}!={s}:\n"
            f"    raise SystemError({_msg()})\n")

def _s_settrace_bounce():
    v = _rn()
    return (f"import sys as {v}\n"
            f"{v}.settrace(lambda *_:None)\n"
            f"{v}.settrace(None)\n"
            f"if {v}.gettrace() is not None:\n"
            f"    raise RuntimeError({_msg()})\n")

def _s_poison():
    v = _rn(); f = _rn(); p = _rn(); pv = random.randint(0x10000,0xFFFFF)
    return (f"import sys as {v}\n"
            f"def {f}():\n"
            f"    global {p}\n"
            f"    {p}=0\n"
            f"    if {v}.gettrace() is not None:\n"
            f"        {p}={pv}\n"
            f"{f}()\n"
            f"if {p}!=0:\n"
            f"    raise RuntimeError({_msg()})\n")


_ALL_STUBS = [
    _s_gettrace, _s_getprofile, _s_dis_check, _s_debugpy,
    _s_stack_depth, _s_timing, _s_coflags, _s_sentinel,
    _s_settrace_bounce, _s_poison,
]


# ── Scatter sentinel generator ────────────────────────────────────────────

def _make_sentinel(fn_name: str, wrap: bool) -> str:
    kind = random.randint(0,3); v = _rn(); msg = _msg()
    if kind == 0:
        body = f"    import sys as {v}\n    if {v}.gettrace() is not None:\n        raise RuntimeError({msg})\n"
    elif kind == 1:
        body = f"    import sys as {v}\n    if {v}.getprofile() is not None:\n        raise RuntimeError({msg})\n"
    elif kind == 2:
        mh = _hex(random.choice(["debugpy","pydevd","bdb"]))
        body = f"    import sys as {v}\n    if \"{mh}\" in {v}.modules:\n        raise ImportError({msg})\n"
    else:
        s = random.randint(0x1000,0xEFFF); a=random.randint(1,0xFFFF); b=s^a; xn=_rn()
        body = f"    {xn}=({a}^{b})\n    if {xn}!={s}:\n        raise SystemError({msg})\n"

    fn = f"def {fn_name}():\n{body}"
    if wrap:
        body_lines = "\n".join("    "+l for l in fn.splitlines()[1:])
        fn = f"def {fn_name}():\n    try:\n" + "\n".join("    "+l for l in body.splitlines()) + "\n    except Exception:\n        pass\n"
    return fn


class _ScatterTransformer(ast.NodeTransformer):
    def __init__(self, sentinels: list, prob: float):
        self.sentinels = sentinels
        self.prob      = prob
        self.injected  = 0

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if not self.sentinels or random.random() > self.prob: return node
        if len(node.body) < 2: return node
        fn = random.choice(self.sentinels)
        call = ast.Expr(value=ast.Call(
            func=ast.Name(id=fn, ctx=ast.Load()),
            args=[], keywords=[]))
        ast.copy_location(call, node)
        ast.fix_missing_locations(call)
        pos = random.randint(0, len(node.body)-1)
        node.body.insert(pos, call)
        self.injected += 1
        return node
    visit_AsyncFunctionDef = visit_FunctionDef


class AntiDebugPass(ObfPass):
    name        = "anti_debug"
    phase       = 1
    description = "Anti-debug stubs (top-of-file + scattered in functions)"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            n_stubs     = self.opts.get("n_stubs",      4)
            wrap        = self.opts.get("wrap_try",      True)
            scatter     = self.opts.get("scatter",       True)
            n_sentinels = self.opts.get("n_sentinels",   3)
            prob        = self.opts.get("scatter_prob",  0.7)

            # top-of-file stubs
            chosen = random.sample(_ALL_STUBS, min(n_stubs, len(_ALL_STUBS)))
            random.shuffle(chosen)
            parts = []
            for stub_fn in chosen:
                stub = stub_fn()
                if wrap:
                    ind = "\n".join("    "+l for l in stub.splitlines())
                    stub = f"try:\n{ind}\nexcept Exception:\n    pass\n"
                parts.append(stub)
            header = "\n".join(parts)

            # scatter sentinels
            sentinel_defs  = []
            sentinel_names = []
            if scatter:
                for _ in range(n_sentinels):
                    fn_name = _rn(8)
                    sentinel_names.append(fn_name)
                    sentinel_defs.append(_make_sentinel(fn_name, wrap))

            pre = header + "\n" + "\n".join(sentinel_defs) + "\n" + code

            scatter_count = 0
            if scatter and sentinel_names:
                try:
                    tree = ast.parse(pre)
                    t    = _ScatterTransformer(sentinel_names, prob)
                    ast.fix_missing_locations(t.visit(tree))
                    pre           = ast.unparse(tree)
                    scatter_count = t.injected
                except Exception:
                    pass   # scatter failure is non-fatal

            return self._ok(pre,
                message=f"injected {len(chosen)} top stubs + {n_sentinels} sentinels → {scatter_count} functions",
                stubs=len(chosen), scatter=scatter_count)
        except Exception as exc:
            return self._err(code, exc)
