"""
MutatingConstPool – self-modifying constant pool.

Vấn đề với version cũ:
  - encode_table dùng state advance LCG theo từng entry
  - nhưng _MCP._decode dùng self._state tại thời điểm get()
  - state tại compile-time khác state tại runtime → mismatch

Fix: encode_table snapshot initial_masks per-idx,
    _MCP lưu initial_masks đó, decode lần đầu dùng initial_mask,
    sau đó re-encode dùng new state để subsequent reads vẫn đúng.

Invariant: decoded_value = raw ^ current_mask
           sau re-encode:  new_raw = decoded_value ^ new_mask
           → get() tiếp theo: new_raw ^ new_mask = decoded_value ✓
"""
from __future__ import annotations
import random

_MASK32 = 0xFFFF_FFFF


def _entry_mask(state: int, idx: int) -> int:
    return (state ^ (idx * 0x9E3779B9)) & _MASK32


class MutatingConstPool:
    """Compile-time helper: encodes const_table, also generates runtime class."""

    def __init__(self, seed: int | None = None):
        self._seed = seed if seed is not None else random.randint(1, _MASK32)

    def encode_table(self, const_table: dict) -> tuple[dict, dict, int]:
        """
        Returns (encoded_pool, initial_masks, seed).
          encoded_pool   : {idx: encoded_val}  – raw storage
          initial_masks  : {idx: mask}         – per-idx initial decode mask
          seed           : int                 – initial state
        """
        state         = self._seed
        encoded       = {}
        initial_masks = {}

        for idx, val in const_table.items():
            iidx = int(idx)
            if isinstance(val, int) and not isinstance(val, bool):
                mask             = _entry_mask(state, iidx)
                encoded[iidx]    = val ^ mask
                initial_masks[iidx] = mask
            else:
                encoded[iidx]    = val
                initial_masks[iidx] = 0

            # Advance per-entry so each entry has unique initial mask
            state = ((state * 0x5851F42D) + iidx + 1) & _MASK32

        return encoded, initial_masks, self._seed

    # ── Runtime class emitted into obfuscated output ──────────────────────
    @staticmethod
    def emit_runtime() -> str:
        return r'''
class _MCP:
    """Self-modifying constant pool – runtime."""
    def __init__(self, pool: dict, masks: dict, seed: int):
        # pool  : {idx: current_encoded_value}
        # masks : {idx: current_decode_mask}
        # seed  : initial state (for state evolution)
        self._pool  = dict(pool)
        self._masks = dict(masks)
        self._state = seed
        self._hist  = []   # [(idx, decoded_int), ...]  last 8

    def get(self, idx):
        raw  = self._pool.get(idx)
        mask = self._masks.get(idx, 0)
        if isinstance(raw, int):
            val = raw ^ mask
        else:
            val = raw

        self._evolve(idx, val)
        return val

    def _evolve(self, idx, decoded):
        # 1. Record history
        hval = decoded if isinstance(decoded, int) else (hash(str(decoded)) & 0xFFFFFFFF)
        self._hist.append((idx, hval))
        if len(self._hist) > 8:
            self._hist = self._hist[-8:]

        # 2. Evolve state using history
        hist_hash    = hash(tuple(self._hist)) & 0xFFFFFFFF
        self._state  = (self._state ^ hval ^ hist_hash) & 0xFFFFFFFF

        # 3. Re-encode this entry with new mask so next read decodes correctly
        if isinstance(self._pool.get(idx), int):
            new_mask         = (self._state ^ (idx * 0x9E3779B9)) & 0xFFFFFFFF
            # decoded ^ new_mask = new_raw
            self._pool[idx]  = decoded ^ new_mask if isinstance(decoded, int) else decoded
            self._masks[idx] = new_mask
'''
