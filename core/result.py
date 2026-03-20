from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ObfResult:
    code:      str
    pass_name: str
    success:   bool = True
    message:   str  = ""
    details:   dict = field(default_factory=dict)

    @property
    def icon(self) -> str:
        return "✓" if self.success else "✗"

    def __str__(self) -> str:
        suffix = f" — {self.message}" if self.message else ""
        return f"[{self.icon}] {self.pass_name}{suffix}"

    def __bool__(self) -> bool:
        return self.success
