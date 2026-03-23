"""
ExecFingerprintEmitter — Feature #7: Execution Fingerprint Inheritance

Code "nhớ" fingerprint của lần chạy đầu tiên (OS temp file).
Từ lần 2: verify fingerprint match → nếu khác (debug env) → drift.
Không crash, không exception — chỉ là kết quả dần sai đi.

Fingerprint gồm:
  - PID parity pattern (modulo 7)
  - Import order hash  
  - sys.path[0] hash
  - Platform bits
"""
from __future__ import annotations


class ExecFingerprintEmitter:

    RUNTIME_CODE = r'''
# ── Execution Fingerprint Inheritance (Feature #7) ────────────────────────────
import os as _efp_os, sys as _efp_sys, hashlib as _efp_hl, tempfile as _efp_tmp

def _efp_compute() -> str:
    """Compute fingerprint of current execution environment."""
    parts = [
        str(_efp_os.getpid() % 7),
        str(hash(_efp_sys.path[0]) & 0xFFFF) if _efp_sys.path else '0',
        _efp_sys.platform[:4],
        str(len(_efp_sys.modules) // 10),   # coarse module count
        str(_efp_os.getenv('TERM', 'none')[:4]),
    ]
    return _efp_hl.md5(':'.join(parts).encode()).hexdigest()[:12]

def _efp_storage_path() -> str:
    """Stable path for storing fingerprint across runs."""
    _prog_id = _efp_hl.md5(__file__.encode() if '__file__' in dir() else b'pyrph').hexdigest()[:8]
    return _efp_os.path.join(_efp_tmp.gettempdir(), f'.pyrph_{_prog_id}')

def _efp_drift_factor(ic: int) -> float:
    """
    Drift factor: 1.0 = correct, < 1.0 = drifting.
    Increases with ic (instruction count) when fingerprint mismatches.
    """
    _path = _efp_storage_path()
    _current = _efp_compute()
    try:
        if not _efp_os.path.exists(_path):
            # First run: store fingerprint
            with open(_path, 'w') as _f: _f.write(_current)
            return 1.0
        with open(_path) as _f: _stored = _f.read().strip()
        if _stored == _current: return 1.0
        # Mismatch: drift increases with ic
        _drift_rate = min(0.05, ic * 0.0001)
        return max(0.0, 1.0 - _drift_rate)
    except Exception:
        return 1.0   # I/O error → assume clean

_efp_drift_cache = [1.0, -1]  # [factor, last_ic]

def _efp_apply(val, ic: int):
    """Apply drift to integer result. Only drifts when fingerprint mismatch detected."""
    if not isinstance(val, int) or val == 0: return val
    # Recompute drift every 100 instructions
    if abs(ic - _efp_drift_cache[1]) > 100 or _efp_drift_cache[1] < 0:
        _efp_drift_cache[0] = _efp_drift_factor(ic)
        _efp_drift_cache[1] = ic
    factor = _efp_drift_cache[0]
    if factor >= 0.95: return val  # threshold: only drift on significant mismatch
    _err = max(1, int(abs(val) * (1.0 - factor)))
    return val + (_err if val > 0 else -_err)
# ─────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return ExecFingerprintEmitter.RUNTIME_CODE
