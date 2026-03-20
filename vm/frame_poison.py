"""
FramePoisoner – XOR-split state registers to defeat frame.f_locals dumping.

Encoding invariant:
    write(i, val):  _a[i] = val ^ k1,  _b[i] = k1 ^ k2
    read_any(i):    to_signed32( _a[i] ^ _b[i] ^ k2 ) = val  ✓

Handles negative integers via to_signed32() after decode.

tick(pc, last_op):
    1. decode each int slot
    2. advance k1 = (k1*MUL + pc) & MASK
                k2 = hash(k1 ^ last_op) & MASK
    3. re-encode with new keys
"""
from __future__ import annotations


class FramePoisoner:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
try:
    import pyrph_core as _NC; _NC_NATIVE = True
except ImportError:
    _NC = None; _NC_NATIVE = False

_FP_MASK = 0xFFFFFFFF
_FP_MUL  = 0x5851F42D
_NONINT  = 0xDEADC0DE

def _fp_s32(n: int) -> int:
    """Interpret MASK-bounded int as signed 32-bit."""
    n &= _FP_MASK
    return n - 0x100000000 if n >= 0x80000000 else n

class _SS:
    """Split-State register bank. Slot encoding: _a=val^k1, _b=k1^k2."""
    __slots__ = ('_a', '_b', '_k1', '_k2')

    def __init__(self, size: int, seed1: int, seed2: int):
        self._a  = [0] * size
        self._b  = [0] * size
        self._k1 = seed1 & _FP_MASK
        self._k2 = seed2 & _FP_MASK

    def write(self, idx: int, val):
        i = idx & 0xF
        if isinstance(val, int):
            if _NC_NATIVE:
                self._a[i], self._b[i] = _NC.ss_write(
                    val & _FP_MASK, self._k1, self._k2)
            else:
                self._a[i] = (val ^ self._k1) & _FP_MASK
                self._b[i] = (self._k1 ^ self._k2) & _FP_MASK
        else:
            self._a[i] = val
            self._b[i] = _NONINT

    def read_any(self, idx: int):
        i = idx & 0xF
        if self._b[i] == _NONINT:
            return self._a[i]
        if _NC_NATIVE:
            return _NC.ss_read(self._a[i], self._b[i], self._k2)
        raw = (self._a[i] ^ self._b[i] ^ self._k2) & _FP_MASK
        return _fp_s32(raw)

    def tick(self, pc: int, last_op: int):
        """Rotate keys and re-encode all integer slots."""
        old_k2   = self._k2
        self._k1 = ((self._k1 * _FP_MUL) + pc) & _FP_MASK
        self._k2 = hash(self._k1 ^ last_op) & _FP_MASK
        for i in range(len(self._a)):
            if self._b[i] != _NONINT:
                if _NC_NATIVE:
                    na, nb, self._k1, self._k2 = _NC.ss_tick(
                        self._a[i], self._b[i], self._k1, self._k2, pc, last_op)
                    self._a[i] = na; self._b[i] = nb
                else:
                    decoded  = _fp_s32((self._a[i] ^ self._b[i] ^ old_k2) & _FP_MASK)
                    self._a[i] = (decoded ^ self._k1) & _FP_MASK
                    self._b[i] = (self._k1 ^ self._k2) & _FP_MASK
'''

    @staticmethod
    def emit_vm3_patch() -> str:
        return (
            "        import os as _os\n"
            "        _fp_s1 = hash(f'{time.time_ns()}{_os.getpid()}a') & 0xFFFFFFFF\n"
            "        _fp_s2 = hash(f'{time.time_ns()}{_os.getpid()}b') & 0xFFFFFFFF\n"
            "        self.R1 = _SS(16, _fp_s1, _fp_s2)\n"
            "        self.R2 = _SS(16, _fp_s2, _fp_s1)\n"
        )
