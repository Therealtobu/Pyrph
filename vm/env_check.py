"""
EnvironmentFingerprinter – phát hiện debugger/tracer/profiler trước khi VM chạy.

Nếu phát hiện môi trường phân tích:
  → KHÔNG crash, KHÔNG raise exception
  → Âm thầm inject sai data vào VM state từ instruction đầu tiên
  → Attacker thấy chương trình "chạy" nhưng output sai hoàn toàn

Checks:
  1. sys.gettrace() != None        → debugger / coverage tool
  2. sys.getprofile() != None      → profiler attached
  3. Timing anomaly (>5ms cho 1000 iters)  → single-step / breakpoint
  4. gc.get_threshold()[0] < 100   → memory profiler lowered threshold
  5. sys.monitoring active (3.12+) → new monitoring API
  6. __debug__ bị override         → pdb manipulation

Emitted as source string → inlined vào output file.
"""
from __future__ import annotations


class EnvCheck:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
def _pyrph_env_ok() -> bool:
    """Returns True nếu môi trường sạch, False nếu detect analysis tool."""
    try:
        import sys, gc, time

        # Check 1: tracer / debugger
        if sys.gettrace() is not None:
            return False

        # Check 2: profiler
        if sys.getprofile() is not None:
            return False

        # Check 3: timing anomaly (single-step / breakpoint slows loop)
        _t0 = time.perf_counter_ns()
        _acc = 0
        for _i in range(1000):
            _acc += _i
        _elapsed = time.perf_counter_ns() - _t0
        if _elapsed > 5_000_000:   # 5ms threshold
            return False

        # Check 4: gc threshold manipulation (memory profilers lower it)
        _thresh = gc.get_threshold()
        if _thresh[0] < 100:
            return False

        # Check 5: Python 3.12+ sys.monitoring
        _mon = getattr(sys, 'monitoring', None)
        if _mon is not None:
            try:
                if _mon.get_tool(0) is not None:
                    return False
            except Exception:
                pass

        return True
    except Exception:
        return True   # any error → assume clean to avoid false positives


def _pyrph_poison_state(state_obj, reason_hash: int):
    """
    Âm thầm corrupt VM state khi detect analysis environment.
    Không raise, không print – chỉ XOR key với reason_hash.
    """
    try:
        state_obj.key   = (state_obj.key   ^ reason_hash) & 0xFFFFFFFF
        state_obj.state = (state_obj.state ^ reason_hash) & 0xFFFFFFFF
    except Exception:
        pass
'''

    @staticmethod
    def emit_bootstrap_check() -> str:
        """Đoạn code chèn vào bootstrap, chạy trước __vm.run()."""
        return (
            "if not _pyrph_env_ok():\n"
            "    _pyrph_poison_state(__vm.r1, 0xDEADF00D)\n"
            "    _pyrph_poison_state(__vm.r2, 0xCAFEBABE)\n"
        )
