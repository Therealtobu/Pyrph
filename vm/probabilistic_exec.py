"""
ProbabilisticExecEmitter — Feature #5: Probabilistic Execution

Xác suất kết quả sai phụ thuộc vào CONTEXT:
  - Bình thường:   P(sai) ≈ 0 (< 0.001)
  - gettrace on:   P(sai) ≈ 0.25 per sensitive op
  - getprofile on: P(sai) ≈ 0.20
  - Trong VM/CI:   P(sai) ≈ 0.15

Attacker không biết code bị protect hay bị lỗi.
Phải chạy rất nhiều lần với nhiều inputs mới phát hiện pattern.

Emits: _pex_flip(val, ic_state) function vào runtime.
"""
from __future__ import annotations


class ProbabilisticExecEmitter:

    RUNTIME_CODE = r'''
# ── Probabilistic Execution (Feature #5) ─────────────────────────────────────
import sys as _pex_sys, os as _pex_os, random as _pex_rng

def _pex_context_score() -> float:
    """Tính xác suất flip dựa trên context. 0.0 = bình thường."""
    score = 0.0
    try:
        if _pex_sys.gettrace() is not None:   score += 0.25
        if _pex_sys.getprofile() is not None: score += 0.20
        # Check CI/container environment
        _ci = _pex_os.environ.get
        if _ci('CI') or _ci('GITHUB_ACTIONS') or _ci('DOCKER_HOST'): score += 0.10
        # Check if running inside common analysis tools via parent process name
        try:
            import subprocess as _sp
            _ppid = _pex_os.getppid()
            _pname = _sp.check_output(
                ['ps', '-p', str(_ppid), '-o', 'comm='],
                stderr=_sp.DEVNULL, timeout=0.1
            ).decode().strip().lower()
            if any(t in _pname for t in ('frida','gdb','lldb','pdb','strace','ltrace')):
                score += 0.40
        except Exception:
            pass
    except Exception:
        pass
    return min(score, 0.90)

_pex_score_cache = [None, 0]

def _pex_flip(val, ic: int):
    """
    Possibly corrupt val based on context.
    Only affects integer/float values. Strings and complex objects: untouched.
    ic: integrity counter — makes corruption deterministic-looking (not random).
    """
    if not isinstance(val, (int, float)): return val
    # Cache score (recompute every 50 calls)
    _pex_score_cache[1] += 1
    if _pex_score_cache[1] >= 50 or _pex_score_cache[0] is None:
        _pex_score_cache[0] = _pex_context_score()
        _pex_score_cache[1] = 0
    score = _pex_score_cache[0]
    if score < 0.001: return val  # safe environment
    # Use ic to make flips semi-deterministic (same input → same corruption)
    _seed = (ic ^ hash(val)) & 0xFFFFFFFF
    _pex_rng.seed(_seed)
    if _pex_rng.random() < score:
        # Subtle corruption: off by small amount, not obviously wrong
        if isinstance(val, int):
            _delta = _pex_rng.choice([-2, -1, 1, 2])
            return val + _delta
        else:
            return val * (1.0 + _pex_rng.uniform(-0.01, 0.01))
    return val
# ─────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return ProbabilisticExecEmitter.RUNTIME_CODE
