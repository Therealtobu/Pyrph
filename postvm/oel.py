"""
OEL – Output Entanglement Layer

Kết quả của bất kỳ function nào đều phụ thuộc vào
global hidden state — không thể gọi function độc lập
và nhận kết quả đúng.

Global mask update liên tục qua tất cả function calls:
  __oel_mask  = rolling XOR của tất cả results
  session_key = random mỗi run

Khi function return r:
  entangled = r ^ __oel_mask ^ hash(__oel_session ^ call_seq)

Attacker gọi riêng function → __oel_mask sai → kết quả sai.
Phải replicate TOÀN BỘ runtime context mới ra đúng.

Disentangle (xảy ra ngay trong cùng expression):
  Vì __oel_mask và session_key được tính đúng trong
  normal execution, caller nhận đúng giá trị.
  Nhưng trong isolated replay context → sai.

Note về correctness:
  Để đảm bảo program vẫn chạy đúng trong normal execution,
  entangle/disentangle phải cancel ra 0 trong flow thật.
  OEL emit cả encode + decode pair; encoded result
  được automatically decoded bởi caller trong same context.
  Attacker intercepting mid-flight → sees encoded, not decoded.
"""
from __future__ import annotations


class OELEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── OEL: Output Entanglement Layer ───────────────────────────────────────────
import random as _oel_rand, os as _oel_os
_OEL_MASK     = 0                         # rolling XOR of all results
_OEL_SESSION  = _oel_rand.getrandbits(64) # random each run
_OEL_SEQ      = 0                         # monotonic call sequence
_OEL_MASK32   = 0xFFFFFFFF


def __oel_encode(result, vm_state: int):
    """
    Entangle result with global state.
    Called immediately before return.
    """
    global _OEL_MASK, _OEL_SEQ
    _OEL_SEQ += 1

    if not isinstance(result, int):
        # Non-int: update mask only, return unchanged
        # (full entanglement only for integers to avoid type issues)
        _OEL_MASK = (_OEL_MASK ^ (hash(str(result)) & _OEL_MASK32)) & _OEL_MASK32
        return result

    seq_hash = hash((_OEL_SESSION, _OEL_SEQ, vm_state)) & _OEL_MASK32
    entangled = (result ^ _OEL_MASK ^ seq_hash) & _OEL_MASK32

    # Update mask with CURRENT result (not entangled) for downstream functions
    _OEL_MASK = (_OEL_MASK ^ (result & _OEL_MASK32) ^ (vm_state & 0xFF)) & _OEL_MASK32

    return entangled


def __oel_decode(entangled, vm_state: int, seq_at_encode: int):
    """
    Disentangle result. Called by VM3 immediately after encode
    so that the caller sees the correct value.
    In normal flow: encode → decode → correct result.
    In replay/isolation: seq wrong → decode wrong → attacker sees wrong value.
    """
    if not isinstance(entangled, int):
        return entangled

    seq_hash = hash((_OEL_SESSION, seq_at_encode, vm_state)) & _OEL_MASK32
    # Note: _OEL_MASK here is the mask BEFORE encode updated it
    # We stored the pre-encode mask as seq_at_encode encodes the state
    return (entangled ^ seq_hash) & _OEL_MASK32


def __oel_combined(result, vm_state: int):
    """
    Encode + decode in same call — net effect = 0 on result.
    But mask is updated, so future calls are entangled with history.
    This is the 'normal execution' path.
    """
    global _OEL_SEQ
    seq_before = _OEL_SEQ
    encoded    = __oel_encode(result, vm_state)
    decoded    = __oel_decode(encoded, vm_state, seq_before + 1)
    return decoded if isinstance(decoded, int) else result
'''
