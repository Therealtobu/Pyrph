"""
MutatingConstPool – self-modifying constant pool.

Design (corrected):
  - Each slot stores (encoded_value, encode_mask) where encode_mask is
    computed from the pool state AT THE TIME that slot was written.
  - get(idx) decodes using the slot's OWN mask (not current state).
  - After decoding, _state mutates based on execution history.
  - The slot is RE-ENCODED using the NEW state's mask for that slot.
  - Other slots keep their own encode_mask until THEY are accessed.

This means:
  - Slot decode is always correct (uses own mask)
  - But that mask keeps changing → snapshot of pool = wrong masks for future
  - Replay attack: different history → different masks → wrong decode
"""
from __future__ import annotations
from typing import Any

_MASK32  = 0xFFFF_FFFF
_GOLDEN  = 0x9E37_79B9
_LCG_MUL = 0x6C62_272E


def _compute_mask(state: int, idx: int) -> int:
    return (state ^ (idx * _GOLDEN)) & _MASK32


class MutatingConstPool:

    def __init__(self, initial: dict[int, Any], seed: int = 0xDEAD_BEEF):
        self._state = seed & _MASK32
        self._log: list[tuple[int, int]] = []

        # Each slot: (encoded_value, mask_used)
        # Encode each with its own mask snapshot at construction time
        self._slots: dict[int, tuple[Any, int]] = {}
        for k, v in initial.items():
            idx  = int(k)
            mask = _compute_mask(self._state, idx)
            if isinstance(v, int) and not isinstance(v, bool):
                self._slots[idx] = (v ^ mask, mask)
            else:
                self._slots[idx] = (v, 0)   # non-int: no encoding

    # ── Public API ────────────────────────────────────────────────────────────
    def get(self, idx) -> Any:
        idx = int(idx)
        if idx not in self._slots:
            return None

        enc_val, mask = self._slots[idx]

        # Decode using the slot's own mask
        if isinstance(enc_val, int) and not isinstance(enc_val, bool):
            result = enc_val ^ mask
        else:
            result = enc_val

        # Mutate state with history
        self._mutate(idx, result)

        # Re-encode this slot with the NEW state's mask
        new_mask = _compute_mask(self._state, idx)
        if isinstance(result, int) and not isinstance(result, bool):
            self._slots[idx] = (result ^ new_mask, new_mask)
        # (non-int slots don't need re-encoding)

        return result

    # ── Internal ──────────────────────────────────────────────────────────────
    def _mutate(self, idx: int, result: Any):
        rh = (result & _MASK32) if isinstance(result, int) \
             else (hash(str(result)) & _MASK32)

        self._log.append((idx, rh))
        if len(self._log) > 8:
            self._log.pop(0)

        history_key = hash(tuple(self._log)) & _MASK32

        s = self._state
        s = (s ^ rh)              & _MASK32
        s = (s ^ history_key)     & _MASK32
        s = ((s * _LCG_MUL) + idx) & _MASK32
        self._state = s

    # ── Export for codegen ────────────────────────────────────────────────────
    def export(self) -> dict:
        """Serialise pool for embedding in output. Returns encoded state."""
        slots_out = {}
        for k, (enc_val, mask) in self._slots.items():
            slots_out[k] = {"e": enc_val, "m": mask}
        return {"slots": slots_out, "state": self._state}

    @classmethod
    def from_export(cls, data: dict) -> "MutatingConstPool":
        obj = cls.__new__(cls)
        obj._state = data["state"]
        obj._log   = []
        obj._slots = {}
        for k, v in data["slots"].items():
            obj._slots[int(k)] = (v["e"], v["m"])
        return obj


# ── Runtime source injected by codegen ───────────────────────────────────────
POOL_RUNTIME = r'''
# ── Mutating Constant Pool ────────────────────────────────────────────────────
_CP_MASK  = 0xFFFFFFFF
_CP_G     = 0x9E3779B9
_CP_MUL   = 0x6C62272E
_CP_STATE = 0
_CP_SLOTS = {}   # idx → [enc_val, mask]
_CP_LOG   = []

def _cp_mask(state, idx):
    return (state ^ (idx * _CP_G)) & _CP_MASK

def _cp_get(idx):
    global _CP_STATE
    idx = int(idx)
    if idx not in _CP_SLOTS:
        return None
    enc_val, mask = _CP_SLOTS[idx]
    # decode
    result = (enc_val ^ mask) if isinstance(enc_val, int) else enc_val
    # mutate
    rh = result & _CP_MASK if isinstance(result, int) else hash(str(result)) & _CP_MASK
    _CP_LOG.append((idx, rh))
    if len(_CP_LOG) > 8:
        _CP_LOG.pop(0)
    hk = hash(tuple(_CP_LOG)) & _CP_MASK
    s  = _CP_STATE
    s  = (s ^ rh)          & _CP_MASK
    s  = (s ^ hk)          & _CP_MASK
    s  = ((s * _CP_MUL) + idx) & _CP_MASK
    _CP_STATE = s
    # re-encode slot
    if isinstance(result, int):
        nm = _cp_mask(s, idx)
        _CP_SLOTS[idx] = [result ^ nm, nm]
    return result
# ─────────────────────────────────────────────────────────────────────────────
'''
