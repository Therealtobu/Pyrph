"""
transforms/strip.py
====================
StripPass — remove comments and compact whitespace.
Phase 1 · runs first so downstream passes work on clean input.
"""
from __future__ import annotations
import re
from ..core.base   import ObfPass
from ..core.result import ObfResult


class StripPass(ObfPass):
    name        = "strip"
    phase       = 1
    description = "Remove comments, strip whitespace"

    def run(self, code: str) -> ObfResult:
        if not self.enabled:
            return self._skip(code)
        try:
            lines = code.splitlines()
            out   = []
            removed = 0
            for line in lines:
                # strip inline comments (not inside strings — simplified but safe)
                stripped = line.rstrip()
                if stripped.lstrip().startswith("#"):
                    removed += 1
                    continue
                # remove inline comment (crude: only if # not in string literals)
                if "#" in stripped:
                    # only strip if no quotes before the #
                    before = stripped.split("#")[0]
                    if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
                        stripped = before.rstrip()
                out.append(stripped)

            # collapse consecutive blank lines to max 1
            result_lines = []
            prev_blank   = False
            for l in out:
                blank = l.strip() == ""
                if blank and prev_blank:
                    continue
                result_lines.append(l)
                prev_blank = blank

            result = "\n".join(result_lines).strip()
            return self._ok(result, message=f"removed {removed} comment lines",
                            removed=removed)
        except Exception as exc:
            return self._err(code, exc)
