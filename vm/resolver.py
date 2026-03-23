"""
PolymorphicOpcodeResolver – runtime opcode resolution with no static map.

Core formula:
    resolved = ((enc ^ key) + state) ^ (state >> 3)

Properties:
  - key  = hash(time_ns + pid + random) → changes every run
  - state = updated after each instruction → changes continuously
  - No opcode_map dict exists anywhere → cannot be dumped
  - Replay impossible: state mutates, so op(t+1) ≠ op(t) for same enc

State mutation:
    state = update_state(state, resolved_op)
    state = (state ^ (state << 5) ^ (resolved_op * 0x9E3779B9)) & 0xFFFFFFFF

Cross-VM key derivation (used by interleaver):
    vm1.key = hash(vm2.state) & 0xFFFFFFFF
    vm2.key = hash(vm1.last_output) & 0xFFFFFFFF
"""
from __future__ import annotations
import os
import random
import time

_MASK32   = 0xFFFF_FFFF
_GOLDEN   = 0x9E37_79B9   # Fibonacci hashing constant


def make_session_key() -> int:
    """Generate a unique key per process run. Called once at VM startup."""
    raw = f"{time.time_ns()}{os.getpid()}{random.getrandbits(64)}"
    return hash(raw) & _MASK32


class OpcodeResolver:
    """
    Stateful opcode resolver.  One instance per VM (VM1 / VM2 have separate
    instances so they carry independent states).
    """

    def __init__(self, key: int | None = None):
        self.key:         int = key if key is not None else make_session_key()
        self.state:       int = self.key ^ 0xDEAD_BEEF
        self.last_output: int = 0

    # ── Core resolve ──────────────────────────────────────────────────────────
    def resolve(self, enc: int) -> int:
        """
        Decode enc → real opcode.
        MUST be called in instruction-execution order; state mutates after each call.
        """
        op             = ((enc ^ self.key) + self.state) ^ (self.state >> 3)
        op            &= _MASK32
        self.last_output = op
        self._advance(op)
        return op

    # ── State mutation ────────────────────────────────────────────────────────
    def _advance(self, resolved_op: int):
        s = self.state
        s = (s ^ (s << 5)) & _MASK32
        s = (s ^ (resolved_op * _GOLDEN)) & _MASK32
        self.state = s

    # ── Encode (compile-time, inverse of resolve at a known state) ────────────
    def encode(self, real_op: int) -> int:
        """
        Produce enc such that resolve(enc) == real_op at the current state.
        State is NOT advanced (encode is compile-time only).
        """
        # resolve: op = ((enc ^ key) + state) ^ (state >> 3)
        # → enc ^ key = (real_op ^ (state >> 3)) - state
        inner = (real_op ^ (self.state >> 3)) - self.state
        enc   = inner ^ self.key
        return enc & _MASK32

    # ── Cross-VM key update ───────────────────────────────────────────────────
    def update_key_from_peer(self, peer_state: int):
        """
        Derive a new key from the peer VM's state.
        Called by scheduler after each cross-VM handoff.
        """
        self.key = hash(peer_state) & _MASK32

    # ── Snapshot (for serialisation / checkpointing) ──────────────────────────
    def snapshot(self) -> dict:
        return {"key": self.key, "state": self.state, "last_output": self.last_output}

    def restore(self, snap: dict):
        self.key         = snap["key"]
        self.state       = snap["state"]
        self.last_output = snap["last_output"]
