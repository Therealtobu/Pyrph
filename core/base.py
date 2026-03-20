from __future__ import annotations
from abc import ABC, abstractmethod
from .result import ObfResult


class ObfPass(ABC):
    name:        str = "unnamed"
    phase:       int = 0
    description: str = ""

    def __init__(self, **opts):
        self.opts    = opts
        self.enabled: bool = opts.get("enabled", True)

    @abstractmethod
    def run(self, code: str) -> ObfResult: ...

    def _skip(self, code: str) -> ObfResult:
        return ObfResult(code=code, pass_name=self.name,
                         success=True, message="skipped")

    def _ok(self, code: str, message: str = "", **kw) -> ObfResult:
        return ObfResult(code=code, pass_name=self.name,
                         success=True, message=message, details=kw)

    def _err(self, code: str, exc: Exception) -> ObfResult:
        return ObfResult(code=code, pass_name=self.name,
                         success=False, message=f"ERROR: {exc}")
