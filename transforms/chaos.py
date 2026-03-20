"""
transforms/chaos.py
====================
ChaosPass — visual chaos formatting (runs LAST in pipeline).

1. Strip blank lines
2. Collapse consecutive simple top-level statements with semicolons
3. Remove spaces around operators on non-string lines
4. Collapse single-body block openers inline: "if x:\n  y" → "if x: y"
5. Inject unicode noise comments at random positions
"""
from __future__ import annotations
import ast
import random
import re
from ..core.base   import ObfPass
from ..core.result import ObfResult

_NOISE_POOL = "░▒▓█▄▀■□●○◆◇▲▼★☆↑↓←→⊕⊗∅∞≈≠≤≥±×"
_BLOCK_KW   = {"def","class","if","elif","else","for","while",
               "try","except","finally","with","async","@"}


def _noise(rng, n=10):
    return "".join(rng.choices(_NOISE_POOL, k=n))


def _first_word(line: str) -> str:
    s = line.strip().split()
    return s[0] if s else ""


def _is_simple(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"): return False
    fw = _first_word(s)
    if fw in _BLOCK_KW: return False
    if s.endswith(":"): return False
    if fw in {"try","except","finally","else","elif","return",
              "yield","raise","break","continue","pass"}: return False
    return True


def _is_continuation(line: str) -> bool:
    return _first_word(line) in {"except","finally","else","elif"}


def _compress(line: str) -> str:
    if '"' in line or "'" in line: return line.rstrip()
    for pat, rep in [
        (r'\s*==\s*','=='),(r'\s*!=\s*','!='),(r'\s*>=\s*','>='),
        (r'\s*<=\s*','<='),(r'\s*\+=\s*','+='),(r'\s*-=\s*','-='),
        (r'\s*\*=\s*','*='),(r'\s*=\s*','='),(r'\s*\+\s*','+'),
        (r'\s*%\s*','%'),(r'\s*\^\s*','^'),(r'\s*&\s*','&'),
        (r'\s*>\s*(?!=)','>'), (r'\s*<\s*(?!=)','<'),
    ]:
        line = re.sub(pat, rep, line)
    return line.rstrip()


def _pack_blocks(lines: list) -> list:
    out = []; i = 0
    while i < len(lines):
        line = lines[i].rstrip(); s = line.strip()
        if s.endswith(":") and not s.startswith("#"):
            fw = _first_word(s)
            if fw not in {"try","except","finally","else","elif","with","async"}:
                if i+1 < len(lines):
                    body   = lines[i+1]; bs = body.strip()
                    bi     = len(body)-len(body.lstrip())
                    ci     = len(line)-len(line.lstrip())
                    more   = (i+2<len(lines) and
                              (len(lines[i+2])-len(lines[i+2].lstrip()))>ci and
                              not _is_continuation(lines[i+2]))
                    cont   = (i+2<len(lines) and _is_continuation(lines[i+2]))
                    if bi>ci and _is_simple(bs) and not more and not cont:
                        out.append(line+" "+_compress(bs)); i+=2; continue
        out.append(line); i+=1
    return out


def _collapse(lines: list, max_len: int, rng) -> list:
    out=[]; bucket=[]
    def flush():
        if bucket: out.append(";".join(bucket)); bucket.clear()
    for raw in lines:
        line = raw.rstrip()
        if not line: continue
        indent = len(line)-len(line.lstrip())
        if indent > 0: flush(); out.append(line); continue
        if _is_continuation(line): flush(); out.append(line); continue
        if _is_simple(line):
            c = _compress(line)
            if bucket and sum(len(b)+1 for b in bucket)+len(c) > max_len: flush()
            bucket.append(c)
        else:
            flush(); out.append(line)
    flush()
    return out


def _inject_noise(lines: list, rng, density: float) -> list:
    return [
        line + f" #{_noise(rng, rng.randint(5,16))}"
        if rng.random()<density and not line.strip().startswith("#")
        else line
        for line in lines
    ]


class ChaosPass(ObfPass):
    name        = "chaos"
    phase       = 99
    description = "Collapse stmts, strip whitespace, inject unicode noise"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            try: ast.parse(code)
            except SyntaxError as e: return self._err(code, e)
            max_len = self.opts.get("max_line_len",  180)
            density = self.opts.get("noise_density", 0.07)
            seed    = self.opts.get("seed",          None)
            rng     = random.Random(seed)

            lines = code.splitlines()
            lines = _pack_blocks(lines)
            lines = _collapse(lines, max_len, rng)
            lines = _inject_noise(lines, rng, density)
            result= "\n".join(lines)

            try: ast.parse(result)
            except SyntaxError:
                # retry without block packing
                lines2 = _collapse(code.splitlines(), max_len, rng)
                lines2 = _inject_noise(lines2, rng, density)
                r2 = "\n".join(lines2)
                try: ast.parse(r2); result = r2
                except SyntaxError:
                    return self._err(code, SyntaxError("chaos broke syntax"))

            b = len(code.splitlines()); a = len(result.splitlines())
            return self._ok(result, message=f"{b}→{a} lines ({a/max(b,1):.2f}x)")
        except Exception as exc:
            return self._err(code, exc)
