"""
transforms/junk.py
===================
JunkPass — sprinkle meaningless top-level dead-code statements.
"""
from __future__ import annotations
import random
import string
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _rname(n=6) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0,n-1)
    raw = raw[:pos]+random.choice(letters)+raw[pos:]
    return "_j" + raw


def _junk_stmt() -> str:
    kind = random.randint(0,4); name = _rname()
    if kind == 0: return f"{name}={random.randint(0,0xFFFF)}"
    if kind == 1: return f"{name}={random.uniform(0,999):.4f}"
    if kind == 2: return f"{name}=None"
    if kind == 3:
        a,b = random.randint(0,0xFFFF), random.randint(0,0xFFFF)
        return f"{name}=[{a},{b},{random.randint(0,0xFFFF)}]"
    inner = _rname(); return f"{name}={{'{inner}':{random.randint(0,0xFFFF)}}}"


class JunkPass(ObfPass):
    name        = "junk"
    phase       = 1
    description = "Inject dead-code junk statements at top-level scope"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            density = self.opts.get("density", 0.15)
            lines   = code.splitlines()
            n_junk  = max(1, int(len(lines) * density))
            top_level = [i for i,l in enumerate(lines) if l and not l[0].isspace()]
            if not top_level: return self._ok(code, message="no top-level lines found")
            # Filter out positions that would break try/except/if structure:
            # 1. Don't insert BEFORE except/finally/else/elif lines
            # 2. Don't insert before lines that are themselves followed by
            #    a continuation keyword (e.g. last line of a try body)
            _CONT = {"except","finally","else","elif"}

            def _line_first_word(idx):
                s = lines[idx].strip().split()
                return s[0] if s else ""

            def _next_first_word(idx):
                for j in range(idx+1, len(lines)):
                    s = lines[j].strip()
                    if s:
                        return s.split()[0] if s.split() else ""
                return ""

            safe_positions = [
                i for i in top_level
                # don't insert BEFORE a continuation line
                if _line_first_word(i) not in _CONT
                # don't insert before a line that is followed by a continuation
                and _next_first_word(i) not in _CONT
            ]
            if not safe_positions:
                return self._ok(code, message="no safe positions for junk")
            positions = sorted(random.sample(safe_positions, min(n_junk, len(safe_positions))))
            out = []
            junk_count = 0
            insert_at  = set(positions)
            for i,l in enumerate(lines):
                if i in insert_at:
                    out.append(_junk_stmt()); junk_count += 1
                out.append(l)
            return self._ok("\n".join(out),
                            message=f"injected {junk_count} junk statement(s)",
                            count=junk_count)
        except Exception as exc:
            return self._err(code, exc)
