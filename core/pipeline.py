from __future__ import annotations
from typing import List, Optional
from .base   import ObfPass
from .result import ObfResult


class Pipeline:
    def __init__(self, passes: Optional[List[ObfPass]] = None):
        self.passes: List[ObfPass] = list(passes or [])

    def add(self, p: ObfPass) -> "Pipeline":
        self.passes.append(p); return self

    def run(self, source: str) -> List[ObfResult]:
        results: List[ObfResult] = []
        code = source
        for p in self.passes:
            if not p.enabled:
                continue
            try:
                r = p.run(code)
            except Exception as exc:
                r = ObfResult(code=code, pass_name=p.name,
                              success=False, message=f"UNHANDLED: {exc}")
            results.append(r)
            if r.success:
                code = r.code
        if not results:
            results.append(ObfResult(code=source, pass_name="pipeline",
                                     message="no passes ran"))
        return results

    def summary(self) -> str:
        lines = [f"Pipeline — {len(self.passes)} passes"]
        for p in self.passes:
            flag = "  " if p.enabled else "✗ "
            lines.append(f"  {flag}{p.name:<30} phase={p.phase}  {p.description}")
        return "\n".join(lines)
