"""
ValueEntanglementEmitter — Feature #6: Value Entanglement

Các biến "liên kết": A encrypted bằng hash(B,C), B bằng hash(A,C)...
Không thể extract một giá trị mà không có đủ context.

Dùng cho: constants quan trọng, API keys, license values.
Emits: _vent_* functions vào runtime.
"""
from __future__ import annotations
import hashlib


class ValueEntanglementEmitter:

    RUNTIME_CODE = r'''
# ── Value Entanglement (Feature #6) ──────────────────────────────────────────
def _vent_key(a: int, b: int, c: int) -> int:
    """Derive entanglement key from 3 values."""
    _h = hashlib.sha256(f"{a}:{b}:{c}".encode()).digest()
    return int.from_bytes(_h[:4], 'big')

def _vent_enc(val: int, peer_a: int, peer_b: int) -> int:
    """Encrypt val using two peer values."""
    k = _vent_key(peer_a, peer_b, val)
    return val ^ k

def _vent_dec(enc: int, peer_a: int, peer_b: int) -> int:
    """Decrypt val using two peer values."""
    # k is derived from DECRYPTED val — need to reverse
    # XOR is self-inverse IF we know k.
    # k = sha256(peer_a:peer_b:original_val)[:4]
    # enc = original_val ^ k
    # → brute force small ints or use Newton iteration for large
    # For obfuscation: we store {enc, peer_a, peer_b} and decrypt lazily
    # Simple approach: store enc and re-derive on access
    # actual decryption: try enc ^ sha256(peer_a:peer_b:candidate) == candidate
    # For small values (< 2^20): linear scan
    _M = 0xFFFFFFFF
    for _candidate in range(0, 1 << 20):
        if (_candidate ^ _vent_key(peer_a, peer_b, _candidate)) == enc:
            return _candidate
    # Fallback for large values: use enc directly (graceful degrade)
    return enc & _M

class _VE:
    """EntangledValue: val depends on 2 peers."""
    __slots__ = ('_e', '_pa', '_pb', '_cache')

    def __init__(self, enc_val: int, peer_a_ref: str, peer_b_ref: str):
        object.__setattr__(self, '_e', enc_val)
        object.__setattr__(self, '_pa', peer_a_ref)   # var name of peer A
        object.__setattr__(self, '_pb', peer_b_ref)   # var name of peer B
        object.__setattr__(self, '_cache', None)

    def _resolve(self, env: dict) -> int:
        cached = object.__getattribute__(self, '_cache')
        if cached is not None: return cached
        enc = object.__getattribute__(self, '_e')
        pa  = object.__getattribute__(self, '_pa')
        pb  = object.__getattribute__(self, '_pb')
        va  = env.get(pa, 0); va = va._e if isinstance(va, _VE) else va
        vb  = env.get(pb, 0); vb = vb._e if isinstance(vb, _VE) else vb
        result = _vent_dec(enc, int(va), int(vb))
        object.__setattr__(self, '_cache', result)
        return result

    def __int__(self):   return object.__getattribute__(self, '_e')
    def __repr__(self):  return repr(object.__getattribute__(self, '_e'))
    def __str__(self):   return str(object.__getattribute__(self, '_e'))
# ─────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return ValueEntanglementEmitter.RUNTIME_CODE

    @staticmethod
    def entangle(val: int, peer_a: int, peer_b: int) -> int:
        """Encrypt val at obfuscation time."""
        k = int.from_bytes(
            hashlib.sha256(f"{peer_a}:{peer_b}:{val}".encode()).digest()[:4], 'big'
        )
        return val ^ k
