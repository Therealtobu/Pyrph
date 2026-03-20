"""
OpcodeResolverV2 – upgraded resolver với Instruction Meaning Rotation.

Công thức:
    base    = ((enc ^ key) + state) ^ (state >> 3)       # layer 1
    rotated = (base ^ (prev_op * 0x6C62272E)) & MASK32   # layer 2: prev op
    final   = (rotated + data_flow) ^ (data_flow << 7)   # layer 3: runtime data

data_flow được VM update sau mỗi STORE_VAR:
    resolver.feed_data(value)

Tại sao không pattern-match được:
    - base     : phụ thuộc state (thay đổi liên tục)
    - rotated  : phụ thuộc opcode VỪA chạy xong (history)
    - final    : phụ thuộc data đang xử lý (runtime)

Drop-in replacement cho OpcodeResolver trong vm/resolver.py.
"""
from __future__ import annotations
import os, random, time

_MASK32 = 0xFFFF_FFFF
_GOLDEN = 0x9E37_79B9
_ROTMUL = 0x6C62_272E


def make_session_key() -> int:
    return hash(f"{time.time_ns()}{os.getpid()}{random.getrandbits(64)}") & _MASK32


class OpcodeResolverV2:

    def __init__(self, key: int | None = None):
        self.key         = key if key is not None else make_session_key()
        self.state       = self.key ^ 0xDEAD_BEEF
        self.prev_op     = 0
        self.data_flow   = 0
        self.last_output = 0

    # ── Resolve (runtime: decode enc → real opcode) ───────────────────────
    def resolve(self, enc: int) -> int:
        base    = ((enc ^ self.key) + self.state) ^ (self.state >> 3)
        base   &= _MASK32
        rotated = (base ^ (self.prev_op * _ROTMUL)) & _MASK32
        final   = (rotated + self.data_flow) ^ ((self.data_flow << 7) & _MASK32)
        final  &= _MASK32

        self.last_output = final
        self.prev_op     = final
        self._advance(final)
        return final

    # ── Encode (compile-time: inverse at known state) ─────────────────────
    def encode(self, real_op: int) -> int:
        """
        Produce enc s.t. resolve(enc) == real_op at current state.
        State NOT advanced (compile-time only).
        Must be called in the exact order instructions will execute.
        """
        # Invert layer 3: final = (rotated + data_flow) ^ (data_flow << 7)
        # → rotated = (final ^ (data_flow << 7)) - data_flow
        final   = real_op
        rotated = ((final ^ ((self.data_flow << 7) & _MASK32)) - self.data_flow) & _MASK32

        # Invert layer 2: rotated = base ^ (prev_op * ROTMUL)
        base    = (rotated ^ (self.prev_op * _ROTMUL)) & _MASK32

        # Invert layer 1: base = ((enc ^ key) + state) ^ (state >> 3)
        # → enc ^ key = (base ^ (state >> 3)) - state
        inner   = (base ^ (self.state >> 3)) - self.state
        enc     = (inner ^ self.key) & _MASK32
        return enc

    # ── VM calls this after each STORE_VAR to update data_flow ───────────
    def feed_data(self, value):
        if isinstance(value, int):
            mixed = value
        else:
            mixed = hash(str(value)) & _MASK32
        self.data_flow = (self.data_flow ^ mixed) & _MASK32

    # ── State mutation (same as v1) ───────────────────────────────────────
    def _advance(self, resolved_op: int):
        s = self.state
        s = (s ^ ((s << 5) & _MASK32)) & _MASK32
        s = (s ^ (resolved_op * _GOLDEN)) & _MASK32
        self.state = s

    # ── Cross-VM key update ───────────────────────────────────────────────
    def update_key_from_peer(self, peer_state: int):
        self.key = hash(peer_state) & _MASK32

    def snapshot(self) -> dict:
        return {k: getattr(self, k) for k in
                ("key", "state", "prev_op", "data_flow", "last_output")}

    def restore(self, snap: dict):
        for k, v in snap.items():
            setattr(self, k, v)
