"""
SharedState – thread-safe state exchange between Python VM3 and Rust Engine.

Holds:
  vm3_state   : int  – Python VM3's current resolver state
  rust_state  : int  – Rust engine's current state
  cross_key   : int  – hash(vm3_state ^ rust_state), updated after each exchange
  last_vm3_out: int  – last output from Python VM3
  last_rust_out: int – last output from Rust engine
  instruction_counter: int – total instructions executed across both engines

Thread safety: threading.Lock() guards all writes.
Interleave index: determines which engine runs next instruction.
"""
from __future__ import annotations
import threading
import hashlib

_MASK32 = 0xFFFF_FFFF


class SharedState:
    """Thread-safe shared state between Python VM3 and Rust Engine."""

    def __init__(self, vm3_seed: int, rust_seed: int):
        self._lock           = threading.Lock()
        self.vm3_state       = vm3_seed  & _MASK32
        self.rust_state      = rust_seed & _MASK32
        self.cross_key       = self._compute_cross_key()
        self.last_vm3_out    = 0
        self.last_rust_out   = 0
        self.instr_counter   = 0
        # Interleave: 0 = Python turn, 1 = Rust turn
        self._interleave_idx = 0
        # Result queues (thread-safe via list + lock)
        self._vm3_results:  list = []
        self._rust_results: list = []

    # ── Cross-key ─────────────────────────────────────────────────────────────
    def _compute_cross_key(self) -> int:
        raw = (self.vm3_state ^ self.rust_state) & _MASK32
        h   = int.from_bytes(
            hashlib.blake2s(raw.to_bytes(4, 'little'),
                            digest_size=4).digest(), 'little'
        )
        return h & _MASK32

    # ── After Python VM3 executes an instruction ──────────────────────────────
    def vm3_commit(self, new_vm3_state: int, output: int):
        with self._lock:
            self.vm3_state      = new_vm3_state & _MASK32
            self.last_vm3_out   = output & _MASK32
            self.cross_key      = self._compute_cross_key()
            self.instr_counter += 1
            self._vm3_results.append(output & _MASK32)
            self._interleave_idx = 1   # Rust's turn next

    # ── After Rust engine executes an instruction ─────────────────────────────
    def rust_commit(self, new_rust_state: int, output: int):
        with self._lock:
            self.rust_state     = new_rust_state & _MASK32
            self.last_rust_out  = output & _MASK32
            self.cross_key      = self._compute_cross_key()
            self.instr_counter += 1
            self._rust_results.append(output & _MASK32)
            self._interleave_idx = 0   # Python's turn next

    # ── Snapshots (for speculative execution) ─────────────────────────────────
    def snapshot(self) -> dict:
        with self._lock:
            return {
                'vm3_state':    self.vm3_state,
                'rust_state':   self.rust_state,
                'cross_key':    self.cross_key,
                'last_vm3_out': self.last_vm3_out,
                'last_rust_out':self.last_rust_out,
                'counter':      self.instr_counter,
                'interleave':   self._interleave_idx,
            }

    def restore(self, snap: dict):
        with self._lock:
            if not isinstance(snap, dict):
                return

            def _as_int(val, default=0):
                try:
                    return int(val) & _MASK32
                except Exception:
                    return default

            self.vm3_state     = _as_int(snap.get('vm3_state'), self.vm3_state)
            self.rust_state    = _as_int(snap.get('rust_state'), self.rust_state)
            self.last_vm3_out  = _as_int(snap.get('last_vm3_out'), self.last_vm3_out)
            self.last_rust_out = _as_int(snap.get('last_rust_out'), self.last_rust_out)
            self.instr_counter = _as_int(snap.get('counter'), self.instr_counter)

            raw_turn = snap.get('interleave', self._interleave_idx)
            try:
                self._interleave_idx = int(raw_turn) & 1
            except Exception:
                pass

            ck = snap.get('cross_key')
            if isinstance(ck, int):
                self.cross_key = ck & _MASK32
            else:
                self.cross_key = self._compute_cross_key()

    # ── Interleave control ────────────────────────────────────────────────────
    def whose_turn(self) -> int:
        """Returns 0 (Python) or 1 (Rust)."""
        with self._lock:
            return self._interleave_idx

    # ── Final combine ─────────────────────────────────────────────────────────
    def combine_results(self, vm3_result, rust_result) -> int:
        """
        Combine Python and Rust partial results using cross_key.
        Both engines must have run → cross_key reflects both states.
        """
        with self._lock:
            ck = self.cross_key
        if not isinstance(vm3_result, int):
            return vm3_result   # non-int: return unchanged
        if not isinstance(rust_result, int):
            return vm3_result
        # XOR fold with cross_key derived mask
        mask = (ck ^ (ck >> 16)) & 0xFFFF
        # encode: vm3_result XOR mask, then XOR with rust_result contribution
        r1   = (vm3_result  ^ mask)           & _MASK32
        r2   = (rust_result ^ (mask ^ 0xFFFF)) & _MASK32
        # Combine: both must be correct for result to be correct
        # net formula cancels to vm3_result when both are legit:
        #   r1 ^ r2 = (vm3^mask) ^ (rust^~mask) = vm3 ^ rust ^ 0xFFFF
        # But we want vm3_result if both clean:
        # Use: vm3 + (rust - vm3) * 0  → only if rust confirms
        # Simple: vm3_result XOR with (rust_result - rust_expected) delta
        # For correctness: rust_result should be hash(vm3_result ^ ck)
        rust_expected = (vm3_result ^ ck) & _MASK32
        delta         = (rust_result ^ rust_expected) & _MASK32
        # If delta == 0 (Rust confirmed) → return vm3_result unchanged
        # If delta != 0 (tampered) → corrupt subtly
        if delta == 0:
            return vm3_result
        noise = (bin(delta).count('1') * 0x9E3779B9) & 0xFF
        return (vm3_result ^ noise) & _MASK32
