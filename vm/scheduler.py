"""
State-Driven Scheduler – decides which VM (VM1 or VM2) executes each
instruction slice using an AC-wave + PRNG + data-dependent formula.

Formula:
    wave   = |sin(cycle * ω + prng_state * 0.001)|
    vm_id  = (int(wave * 0xFF) ^ (exec_state & 0xFF) ^ (data_byte & 0xFF)) & 1

Where:
    ω            = 2π / VM_POLY_PERIOD   (angular frequency)
    prng_state   = LCG updated each cycle
    exec_state   = combined hash of VM1.state XOR VM2.state
    data_byte    = lowest byte of last computed value

Properties:
  - Pattern is non-linear (sin wave) but not pure random
  - Same bytecode + different input data → different VM scheduling
  - Dumping one VM mid-run gives wrong keys (cross-key dependency violated)
  - vm_id(t+1) ≠ f(vm_id(t)) alone; depends on runtime data

Cross-key update (called after every handoff):
    VM1.resolver.key = hash(VM2.resolver.state) & 0xFFFFFFFF
    VM2.resolver.key = hash(VM1.resolver.last_output) & 0xFFFFFFFF
"""
from __future__ import annotations
import math
import random
from .resolver import OpcodeResolver, make_session_key

_MASK32      = 0xFFFF_FFFF
_LCG_MUL     = 0x6C62_272E   # PCG-XSH-RR constant
_LCG_INC     = 0x14057B7EF7  # odd increment


class Scheduler:
    def __init__(self, period: int = 32, seed: int | None = None):
        self.period      = period
        self.omega       = 2 * math.pi / period
        self.prng_state  = seed if seed is not None else make_session_key()
        self.cycle       = 0

    # ── Main selection ────────────────────────────────────────────────────────
    def pick_vm(self, resolver1: OpcodeResolver,
                resolver2: OpcodeResolver,
                last_data: int = 0) -> int:
        """
        Returns 0 (VM1) or 1 (VM2).

        resolver1 / resolver2 carry the live state of VM1 and VM2 so the
        decision depends on actual runtime state, not just a cycle counter.
        """
        # AC wave component
        wave      = abs(math.sin(self.cycle * self.omega +
                                 self.prng_state * 0.001))
        wave_byte = int(wave * 0xFF) & 0xFF

        # Execution state component (XOR of both VM states)
        exec_state = (resolver1.state ^ resolver2.state) & 0xFF

        # Data component
        data_byte  = last_data & 0xFF

        vm_id = (wave_byte ^ exec_state ^ data_byte) & 1

        # Advance PRNG (LCG step)
        self.prng_state = ((self.prng_state * _LCG_MUL) + _LCG_INC) & _MASK32
        self.cycle     += 1

        return vm_id

    # ── Cross-key update (called after every VM handoff) ─────────────────────
    @staticmethod
    def cross_update(resolver1: OpcodeResolver, resolver2: OpcodeResolver):
        """
        Mutually update keys from peer state.
        After this: dumping VM1 alone gives wrong VM2 decoding, and vice versa.
        """
        new_key1 = hash(resolver2.state) & _MASK32
        new_key2 = hash(resolver1.last_output) & _MASK32
        resolver1.key = new_key1
        resolver2.key = new_key2

    # ── Batch schedule (used by interleaver at compile time) ──────────────────
    def schedule_sequence(self, n: int, seed_state1: int,
                          seed_state2: int) -> list[int]:
        """
        Pre-generate a vm_id sequence for n instructions given seed states.
        This is used at COMPILE TIME by the interleaver to assign vm_slot
        to each IR instruction.  At runtime the same formula is replayed
        with live states, giving the same result if no tampering occurred.
        """
        r1 = OpcodeResolver(key=seed_state1)
        r2 = OpcodeResolver(key=seed_state2)
        sched = Scheduler(period=self.period, seed=self.prng_state)
        result = []
        for _ in range(n):
            vm_id = sched.pick_vm(r1, r2, last_data=r1.last_output)
            result.append(vm_id)
            self.cross_update(r1, r2)
        return result
