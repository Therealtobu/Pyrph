"""
ParallelCoordinator – orchestrates 3-mode hybrid execution.

Splits bytecode between Python VM3 and Rust Engine:
  Even-indexed instructions → Python VM3
  Odd-indexed  instructions → Rust Engine

Execution flow (interleaved):
  1. Python executes instruction[0] → commits state to SharedState
  2. Rust reads cross_key from SharedState (includes Python state)
  3. Rust executes instruction[1] → commits state to SharedState
  4. Python reads cross_key from SharedState (includes Rust state)
  5. ... repeat

Thread parallel (Mode 1):
  Both engines run concurrently, synchronize via SharedState.

IPC simulation (Mode 2):
  RustEngine pretends to be a separate process by operating on
  an isolated copy of state. In production with .so, this becomes
  true multi-process via PyO3 spawn.

Final combine:
  result = SharedState.combine_results(vm3_result, rust_confirmation)
  rust_confirmation = hash(vm3_result ^ cross_key)
  → If either engine tampered: combine detects and corrupts subtly.

Emitter: generates Python source that embeds coordinator logic into
the obfuscated output file.
"""
from __future__ import annotations
import threading
from typing import Any

from .shared_state import SharedState
from .rust_engine   import RustEngine

_MASK32 = 0xFFFF_FFFF


class ParallelCoordinator:
    """
    Coordinates Python VM3 + Rust Engine for a single function execution.
    """

    def __init__(self, bytecode: list, const_table: dict,
                 vm3_seed: int, rust_seed: int):
        # Split bytecode: even → Python, odd → Rust
        self._bc_python = [ins for i, ins in enumerate(bytecode) if i % 2 == 0]
        self._bc_rust   = [ins for i, ins in enumerate(bytecode) if i % 2 == 1]
        self._shared    = SharedState(vm3_seed, rust_seed)
        self._rust_eng  = RustEngine(self._shared, self._bc_rust, const_table)
        self._vm3_result  = None
        self._rust_result = None

    # ── Mode 1+3: Interleaved + Threaded execution ────────────────────────────
    def run_interleaved(self, vm3_instance, init_env: dict) -> Any:
        """
        Run Python VM3 and Rust Engine in interleaved mode.
        vm3_instance: the _VM3 object from the emitted runtime.
        """
        env = dict(init_env)
        self._rust_eng._env.update(env)

        bc_full    = list(vm3_instance.bc)   # full bytecode
        vm3_result = None
        rust_result = None

        i = 0
        while i < len(bc_full):
            ins = bc_full[i]
            turn = self._shared.whose_turn()

            if turn == 0:   # Python's turn
                # Execute in Python VM3
                enc = ins.get("e", 0)
                ops = ins.get("o", [])
                lbl = ins.get("l")
                a   = ins.get("a", 0)
                b   = ins.get("b", 0)
                tmp = ins.get("t")
                bk  = ins.get("bk", 0)

                # Inject cross_key into Python resolver
                vm3_instance.r1.data_flow ^= (self._shared.cross_key & 0xFF)

                op  = vm3_instance.r1.resolve(enc)
                vm3_instance._v1(op & 0xFF, ops, lbl, a, b, tmp,
                                  _enc=enc, _bk=bk)
                if vm3_instance.ret is not vm3_instance._done:
                    vm3_result = vm3_instance.ret
                    break

                # Commit Python state
                out = vm3_instance.r1.last_output
                self._shared.vm3_commit(vm3_instance.r1.state, out)

            else:   # Rust's turn
                # Execute in Rust Engine
                rust_out = self._rust_eng.exec_one(ins)
                rust_result = rust_out

            i += 1

        # Final combine
        if vm3_result is None:
            vm3_result = vm3_instance.env.get("__ret", 0)
        rust_conf = self._rust_eng.confirmation_value(
            vm3_result if isinstance(vm3_result, int) else 0
        )
        final = self._shared.combine_results(
            vm3_result if isinstance(vm3_result, int) else vm3_result,
            rust_conf,
        )
        self._vm3_result  = vm3_result
        self._rust_result = rust_conf
        return final

    # ── Mode 2: Process-parallel simulation ───────────────────────────────────
    def run_process_parallel(self, vm3_instance, init_env: dict) -> Any:
        """
        Simulate process-parallel: Rust runs in thread but with isolated state.
        In production: Rust subprocess communicates via unix socket.
        """
        vm3_result   = [None]
        rust_result  = [None]
        vm3_done     = threading.Event()
        rust_done    = threading.Event()

        def run_vm3():
            # Run Python VM3 normally
            res = vm3_instance.run(init_env)
            vm3_result[0] = res
            vm3_done.set()

        def run_rust():
            # Rust engine processes its bc partition
            r_env = dict(init_env)
            for ins in self._bc_rust:
                self._rust_eng.exec_one(ins)
            rust_result[0] = self._rust_eng.confirmation_value(
                vm3_result[0] if vm3_result[0] is not None and
                                  isinstance(vm3_result[0], int) else 0
            )
            rust_done.set()

        t_vm3 = threading.Thread(target=run_vm3, daemon=True)
        t_rust = threading.Thread(target=run_rust, daemon=True)

        t_vm3.start()
        t_rust.start()

        t_vm3.join(timeout=30)
        t_rust.join(timeout=30)

        # Combine results
        vm3_r  = vm3_result[0]
        rust_r = rust_result[0] or 0
        final  = self._shared.combine_results(
            vm3_r if isinstance(vm3_r, int) else 0,
            rust_r,
        )
        return final if isinstance(vm3_r, int) else vm3_r


class ParallelCoordinatorEmitter:
    """Emits coordinator runtime code into obfuscated output."""

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── Parallel Dual-Engine Coordinator ─────────────────────────────────────────
import threading as _pe_threading, hashlib as _pe_hashlib

_PE_MASK   = 0xFFFFFFFF
_PE_GLD    = 0x9E3779B9

def _pe_cross_key(vm3_state: int, rust_state: int) -> int:
    raw = (vm3_state ^ rust_state) & _PE_MASK
    h   = int.from_bytes(
        _pe_hashlib.blake2s(raw.to_bytes(4, 'little'), digest_size=4).digest(),
        'little'
    )
    return h & _PE_MASK

class _PEState:
    """Shared mutable state between Python VM3 and Rust engine."""
    def __init__(self, v_seed: int, r_seed: int):
        self._lk         = _pe_threading.Lock()
        self.vm3_state   = v_seed & _PE_MASK
        self.rust_state  = r_seed & _PE_MASK
        self.cross_key   = _pe_cross_key(v_seed, r_seed)
        self.last_vm3    = 0
        self.last_rust   = 0
        self.turn        = 0   # 0=python, 1=rust
        self.ic          = 0   # instruction counter

    def vm3_commit(self, state: int, out: int):
        with self._lk:
            self.vm3_state = state & _PE_MASK
            self.last_vm3  = out   & _PE_MASK
            self.cross_key = _pe_cross_key(self.vm3_state, self.rust_state)
            self.turn = 1; self.ic += 1

    def rust_commit(self, state: int, out: int):
        with self._lk:
            self.rust_state = state & _PE_MASK
            self.last_rust  = out   & _PE_MASK
            self.cross_key  = _pe_cross_key(self.vm3_state, self.rust_state)
            self.turn = 0; self.ic += 1

    def combine(self, vm3_r, rust_r) -> object:
        with self._lk:
            ck = self.cross_key
        if not isinstance(vm3_r, int):
            return vm3_r
        # rust_r should equal hash(vm3_r ^ ck) for clean execution
        expected_rust = (vm3_r ^ ck) & _PE_MASK
        rust_v = rust_r if isinstance(rust_r, int) else 0
        delta  = (rust_v ^ expected_rust) & _PE_MASK
        if delta == 0:
            return vm3_r     # clean → unchanged
        noise = (bin(delta).count('1') * _PE_GLD) & 0xFF
        return (vm3_r ^ noise) & _PE_MASK   # silent corruption


def _pe_rust_confirmation(vm3_result: int, cross_key: int) -> int:
    """Value Rust engine should produce to confirm vm3_result."""
    return (vm3_result ^ cross_key) & _PE_MASK


def _pe_apply(vm3_result, vm3_state: int, rust_state: int):
    """
    Post-execution parallel combine.
    Called after _VM3.run() returns, before PostVM layers.
    """
    if not isinstance(vm3_result, int):
        return vm3_result
    ck        = _pe_cross_key(vm3_state, rust_state)
    rust_conf = _pe_rust_confirmation(vm3_result, ck)

    # If NC available: Rust engine's peil_checkpoint doubles as confirmation
    if _NC_NATIVE:
        rust_conf_nc = _NC.peil_checkpoint(vm3_state, rust_state, 0, 0, 0)
        delta = (rust_conf_nc ^ rust_conf) & 0xFFFF
        if delta > 0x100:
            noise = (bin(delta).count('1') * _NC.peil_corrupt(1, delta)) & 0xFF
            return (vm3_result ^ noise) & 0xFFFFFFFF

    state_obj = _PEState(vm3_state, rust_state)
    return state_obj.combine(vm3_result, rust_conf)
'''

    @staticmethod
    def emit_bootstrap() -> str:
        """Inject into bootstrap after __vm setup."""
        return (
            "# Parallel engine state\n"
            "__pe_vm3_state  = lambda: (__vm.r1.state ^ __vm.r2.state) & 0xFFFFFFFF\n"
            "__pe_rust_state = __K1 ^ __K2   # seed from both keys\n"
        )
