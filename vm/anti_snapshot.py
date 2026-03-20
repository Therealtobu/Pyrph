"""
AntiSnapshot – entangles VM state với wall clock.
"""
from __future__ import annotations

_DEFAULT_PERIOD = 64
_TIME_MASK      = 0xFFF
_PID_PERIOD     = 128


class AntiSnapshot:

    @staticmethod
    def emit_runtime(period: int = _DEFAULT_PERIOD) -> str:
        lines = [
            "import time as _time_mod, os as _os_mod",
            f"_AS_PERIOD  = {period}",
            f"_AS_TMASK   = {_TIME_MASK}",
            f"_AS_PPERIOD = {_PID_PERIOD}",
            "",
            "def _anti_snap_tick(res1, res2, ic):",
            "    if ic % _AS_PERIOD == 0:",
            "        _t = _time_mod.perf_counter_ns() & _AS_TMASK",
            "        res1.data_flow = (res1.data_flow ^ _t) & 0xFFFFFFFF",
            "        res2.data_flow = (res2.data_flow ^ _t) & 0xFFFFFFFF",
            "    if ic % _AS_PPERIOD == 0:",
            "        _p = _os_mod.getpid() & 0xFF",
            "        res1.data_flow = (res1.data_flow ^ (_p * 0x9E3779B9)) & 0xFFFFFFFF",
            "        res2.data_flow = (res2.data_flow ^ (_p * 0x6B84C5A3)) & 0xFFFFFFFF",
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def emit_vm3_tick_call() -> str:
        # 12 spaces = 3 levels indent (inside while loop inside run method)
        return "            _anti_snap_tick(self.r1, self.r2, self.pc)\n"
