"""
transforms/anti_dump.py
========================
AntiDumpPass — inject runtime anti-dump and anti-decompiler tricks.

Techniques:
  1. Module watcher — crash if decompiler modules are loaded
  2. Dis blocker    — replace dis.dis with a broken stub
  3. Anti-emulation — environment + timing checks (opt-in, default OFF
                      to avoid false positives in containers/CI)
  4. Code wiper     — overwrite __code__.co_code after func definition
"""
from __future__ import annotations
import ast
import random
import string
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _rn(n: int = 6) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0, n-1)
    return "_" + raw[:pos] + random.choice(letters) + raw[pos:]


def _hex(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)


_DECOMPILER_MODULES = [
    "uncompyle6", "decompile3", "decompyle3", "pycdc",
    "xdis", "spark_parser", "uncompyle2",
]


def _gen_module_watcher() -> str:
    """Crash if known decompiler modules are present in sys.modules."""
    v    = _rn()
    bad  = [_hex(m) for m in _DECOMPILER_MODULES]
    # Build as runtime string comparison to avoid literal module names
    checks = " or ".join(f'"{m}" in {v}.modules' for m in bad)
    return (
        f"try:\n"
        f"    import sys as {v}\n"
        f"    if {checks}:\n"
        f"        raise PermissionError('\\x61\\x63\\x63\\x65\\x73\\x73 denied')\n"
        f"except PermissionError:\n"
        f"    raise\n"
        f"except Exception:\n"
        f"    pass\n"
    )


def _gen_anti_emulation() -> str:
    """
    Detect sandbox via timing only (no env var check — avoids container FP).
    A tight loop completing < 1ns means the clock is fake.
    """
    vt = _rn(); vc = _rn()
    return (
        f"try:\n"
        f"    import time as {vt}\n"
        f"    {vc}={vt}.perf_counter()\n"
        f"    for _i in range(1000):pass\n"
        f"    if {vt}.perf_counter()-{vc}<1e-10:\n"
        f"        raise PermissionError('\\x61\\x63\\x63\\x65\\x73\\x73 denied')\n"
        f"except PermissionError:\n"
        f"    raise\n"
        f"except Exception:\n"
        f"    pass\n"
    )


def _gen_dis_blocker() -> str:
    """Replace dis.dis with a broken stub."""
    v = _rn()
    return (
        f"try:\n"
        f"    import dis as {v}\n"
        f"    {v}.dis = lambda *a,**k: (_ for _ in ()).throw("
        f"TypeError('argument must be a code object'))\n"
        f"except Exception:\n"
        f"    pass\n"
    )


def _gen_code_wiper(fn_name: str) -> str:
    """
    Attempt to overwrite co_code bytes of a function after definition.
    Works on CPython 3.8+ via ctypes buffer trick.
    Safe failure — wrapped in try/except.
    """
    vct = _rn(); vco = _rn(); vbuf = _rn()
    return (
        f"try:\n"
        f"    import ctypes as {vct}\n"
        f"    {vco}={fn_name}.__code__\n"
        f"    {vbuf}=({vct}.c_char*len({vco}.co_code)).from_address(\n"
        f"        id({vco}.co_code)+{vct}.sizeof({vct}.c_long)*2+"
        f"{vct}.sizeof({vct}.c_ssize_t))\n"
        f"    for _i in range(len({vco}.co_code)):\n"
        f"        {vbuf}[_i]=0\n"
        f"except Exception:\n"
        f"    pass\n"
    )


class AntiDumpPass(ObfPass):
    name        = "anti_dump"
    phase       = 1
    description = "Anti-dump: module watcher, dis blocker, code wiper"

    def run(self, code: str) -> ObfResult:
        if not self.enabled:
            return self._skip(code)
        try:
            # Default checks: modules + dis only (no emulation — avoids container FP)
            checks = self.opts.get("checks", ["modules", "dis"])

            parts = []
            count = 0

            if "modules" in checks:
                parts.append(_gen_module_watcher())
                count += 1

            if "emulation" in checks:
                parts.append(_gen_anti_emulation())
                count += 1

            if "dis" in checks:
                parts.append(_gen_dis_blocker())
                count += 1

            if "wipe" in checks:
                try:
                    tree   = ast.parse(code)
                    fnames = [
                        n.name for n in ast.walk(tree)
                        if isinstance(n, ast.FunctionDef) and n.col_offset == 0
                    ]
                    for fn in fnames[:3]:
                        parts.append(_gen_code_wiper(fn))
                        count += 1
                except Exception:
                    pass

            header = "\n".join(parts)
            result = (header + "\n" + code) if header else code

            # Validate syntax before returning
            try:
                ast.parse(result)
            except SyntaxError as e:
                return self._err(code, e)

            return self._ok(
                result,
                message=f"injected {count} anti-dump check(s)",
                count=count,
            )
        except Exception as exc:
            return self._err(code, exc)
