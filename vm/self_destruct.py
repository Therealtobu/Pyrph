"""
SelfDestructEmitter — File Self-Destruct on Tamper Detection

Khi phát hiện tamper/hook:
1. Tìm file .py đang chạy qua call stack
2. Overwrite với random garbage (3 pass)
3. Xóa file + exit(0)

Chỉ ảnh hưởng file obfuscated của chính mình.
"""
from __future__ import annotations


class SelfDestructEmitter:

    RUNTIME_CODE = r'''
# ── Self-Destruct on Tamper ────────────────────────────────────────────────────
import os as _sd_os, sys as _sd_sys, random as _sd_rng

def _sd_wipe_self():
    """Overwrite + xóa file .py đang chạy. Chỉ file obfuscated."""
    try:
        _target = None
        _cands = []
        if _sd_sys.argv: _cands.append(_sd_sys.argv[0])
        _cands.append(globals().get('__file__', ''))
        try:
            import traceback as _sdtb
            for _fi in _sdtb.extract_stack():
                _fn = getattr(_fi, 'filename', '')
                if _fn.endswith('.py'): _cands.append(_fn)
        except Exception: pass
        for _c in _cands:
            if _c and _sd_os.path.isfile(str(_c)) and str(_c).endswith('.py'):
                _target = str(_c); break
        if not _target: return
        _sz = _sd_os.path.getsize(_target)
        _sd_rng.seed()
        with open(_target, 'wb') as _f:
            for _ in range(3):   # 3-pass overwrite
                _f.seek(0)
                _f.write(bytes(_sd_rng.randint(0,255) for _ in range(_sz)))
                _f.flush()
        with open(_target, 'wb') as _f: _f.write(b'\x00' * _sz)  # null pass
        _sd_os.remove(_target)
    except Exception: pass
    finally:
        try: _sd_sys.exit(0)
        except Exception: pass

_sd_triggered = [False]
_sd_score = [0]

def _sd_check(reason: str = ''):
    """2 strikes → wipe. Fast response to tamper."""
    if _sd_triggered[0]: return
    _sd_score[0] += 1
    if _sd_score[0] >= 2:
        _sd_triggered[0] = True
        _sd_wipe_self()
# ──────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return SelfDestructEmitter.RUNTIME_CODE
