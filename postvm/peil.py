"""
PEIL – Post-Execution Integrity Layer

Sau khi mỗi function trong VM3 return, kết quả bị verify
bằng hash của (VM state cuối + SAG state + call trace).

Nếu attacker patch để skip logic trong VM:
  → VM state cuối sẽ khác expected
  → __peil_verify() phát hiện mismatch
  → Modify result nhẹ theo corruption formula
  → Không crash, không raise – chỉ sai subtly

Tại sao khó detect:
  - Output trông hợp lý (off by 1, flipped bit, shifted value)
  - Chỉ sai khi execution path bị alter
  - Không có error message nào

Corruption formula:
  degree  = hamming_distance(actual_hash, expected_hash) & 0xF
  corrupt = (result ^ (degree * 0x9E3779B9)) & MASK
  → degree=0 (unmodified) → corrupt = result ^ 0 = result ✓
  → degree>0 (patched)    → result bị XOR với noise
"""
from __future__ import annotations


class PEILEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── PEIL: Post-Execution Integrity Layer ─────────────────────────────────────
try:
    import pyrph_core as _NC; _NC_NATIVE = True
except ImportError:
    _NC = None; _NC_NATIVE = False

_PEIL_MASK   = 0xFFFFFFFF
_PEIL_GOLDEN = 0x9E3779B9
_PEIL_HIST   = []       # rolling call trace: [(fn_hash, result_hash), ...]
_PEIL_DEPTH  = 0        # current call depth
_PEIL_COUNT  = 0        # total call count


def __peil_enter(fn_id: int):
    """Call at start of each protected function."""
    global _PEIL_DEPTH, _PEIL_COUNT
    _PEIL_DEPTH += 1
    _PEIL_COUNT += 1


def __peil_exit(fn_id: int):
    """Call at end of each protected function."""
    global _PEIL_DEPTH
    _PEIL_DEPTH = max(0, _PEIL_DEPTH - 1)


def __peil_checkpoint(vm_state: int, sag_state: int) -> int:
    """
    Compute expected integrity hash at a given execution point.
    Called at key points inside VM3 execution.
    """
    hist_h = hash(tuple(_PEIL_HIST[-4:])) & _PEIL_MASK if _PEIL_HIST else 0
    if _NC_NATIVE:
        return _NC.peil_checkpoint(vm_state, sag_state, _PEIL_DEPTH, _PEIL_COUNT, hist_h)
    # Use multiplicative mixing to avoid XOR symmetry collisions
    mixed = (vm_state * 0x9E3779B9 + sag_state) & _PEIL_MASK
    mixed = (mixed ^ hist_h ^ (_PEIL_DEPTH * 0x5851F42D) ^ (_PEIL_COUNT * 0x6C62272E)) & _PEIL_MASK
    return mixed


def __peil_verify(result, checkpoint_expected: int,
                  vm_state: int, sag_state: int):
    """
    Verify result integrity. Returns result if OK, corrupted value if not.
    Corruption is subtle: off-by-small-amount for numbers, silent for objects.
    """
    actual = __peil_checkpoint(vm_state, sag_state)
    diff   = actual ^ checkpoint_expected

    if diff == 0:
        # Clean execution – record and return unchanged
        _PEIL_HIST.append(hash(str(result)) & _PEIL_MASK)
        if len(_PEIL_HIST) > 8:
            _PEIL_HIST.pop(0)
        return result

    # Mismatch detected → corrupt subtly
    if _NC_NATIVE:
        return _NC.peil_corrupt(result, diff)
    degree = bin(diff).count('1') & 0xF
    noise  = (degree * _PEIL_GOLDEN) & _PEIL_MASK

    if isinstance(result, int):
        if _NC_NATIVE:
            return _NC.peil_corrupt(result, diff)
        corrupted = (result ^ noise) & _PEIL_MASK
        if -1000 < result < 1000:
            corrupted = result + (degree & 3) - 1
        return corrupted
    elif isinstance(result, str):
        if result and degree > 4:
            # Flip one character
            idx = noise % len(result)
            corrupted = result[:idx] + chr(ord(result[idx]) ^ 1) + result[idx+1:]
            return corrupted
        return result
    elif isinstance(result, list) and result and degree > 8:
        # Rotate list by 1
        return result[1:] + result[:1]
    elif isinstance(result, bool):
        return result ^ (degree > 8)

    # Complex objects: return as-is (corruption too risky)
    return result
'''

    @staticmethod
    def emit_vm3_integration() -> str:
        """
        Code to inject into _VM3 for PEIL tracking.
        Adds __peil_enter/__peil_exit calls around function execution.
        """
        return (
            "        # PEIL: record function entry\n"
            "        _peil_fn_id = hash(str(id(self))) & 0xFFFFFFFF\n"
            "        __peil_enter(_peil_fn_id)\n"
            "        # PEIL: compute initial checkpoint\n"
            "        _peil_sag = globals().get('__sag_state', 0)\n"
            "        _peil_ckpt = __peil_checkpoint(self.r1.state ^ self.r2.state, _peil_sag)\n"
        )

    @staticmethod
    def emit_vm3_return_wrap() -> str:
        """Wrap return value through PEIL verify."""
        return (
            "        __peil_exit(_peil_fn_id)\n"
            "        _peil_sag_end = globals().get('__sag_state', 0)\n"
            "        return __peil_verify(\n"
            "            self.ret,\n"
            "            _peil_ckpt,\n"
            "            self.r1.state ^ self.r2.state,\n"
            "            _peil_sag_end,\n"
            "        )\n"
        )
