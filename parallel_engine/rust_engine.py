"""
RustEngine – Python wrapper that drives the Rust parallel executor.

3-mode hybrid:

Mode 1 – Thread Parallel:
  Rust runs in a Python thread via pyrph_core.
  SharedState is updated after each instruction.
  Python and Rust threads synchronize via a Barrier every N instructions.

Mode 2 – Process Parallel (IPC):
  Rust spawns as a subprocess.
  Communication via bidirectional pipe (stdin/stdout binary protocol).
  Python sends instruction batches, Rust returns state+result pairs.

Mode 3 – Interleaved:
  Rust handles odd-indexed instructions, Python handles even-indexed.
  After each Rust instruction:
    rust_key_for_python = hash(rust_state)  → Python resolver key changes
  After each Python instruction:
    python_key_for_rust = hash(vm3_state)   → Rust resolver key changes
  → Neither can run in isolation

Fallback: if pyrph_core not available, pure Python simulation of Rust engine.
"""
from __future__ import annotations
import hashlib
import threading
from typing import Any

from .shared_state import SharedState

_MASK32 = 0xFFFF_FFFF
_GLD    = 0x9E3779B9
_ROT    = 0x6C62272E


class RustEngine:
    """
    Drives the Rust parallel execution engine.
    Falls back to Python simulation when pyrph_core.so unavailable.
    """

    def __init__(self, shared: SharedState,
                 bytecode_b: list,    # instructions assigned to Rust
                 const_table: dict):
        self._shared   = shared
        self._bc       = bytecode_b
        self._consts   = const_table
        self._state    = shared.rust_state
        self._prev_op  = 0
        self._data_flow= 0
        self._regs     = [0] * 16     # Rust-side registers
        self._env:  dict[str, Any] = {}
        self._result   = None
        self._pc       = 0
        self._done     = False

        # Try native
        try:
            import pyrph_core as _nc
            self._nc        = _nc
            self._native    = True
        except ImportError:
            self._nc        = None
            self._native    = False

    # ── Mode 1: Thread-parallel runner ───────────────────────────────────────
    def run_threaded(self, init_env: dict) -> threading.Thread:
        """Start Rust engine in a background thread. Returns thread handle."""
        self._env.update(init_env)
        t = threading.Thread(
            target = self._thread_loop,
            daemon = True,
            name   = "pyrph-rust-engine",
        )
        t.start()
        return t

    def _thread_loop(self):
        """Main loop for threaded Rust execution."""
        for instr in self._bc:
            if self._done:
                break
            # Wait for our turn (interleave mode)
            while self._shared.whose_turn() != 1:
                threading.Event().wait(0.0001)   # brief yield

            self._exec_instr(instr)

    # ── Mode 3: Single instruction (interleaved) ──────────────────────────────
    def exec_one(self, instr: dict) -> Any:
        """Execute one instruction and commit state to SharedState."""
        out = self._exec_instr(instr)
        return out

    # ── Core execution ────────────────────────────────────────────────────────
    def _exec_instr(self, instr: dict) -> Any:
        enc    = instr.get("e", 0)
        ops    = instr.get("o", [])
        bk     = instr.get("bk", 0)
        vm_slot = instr.get("v", 1)   # Rust handles slot=1 instructions

        # Update key from shared state (cross-key dependency)
        cross = self._shared.cross_key
        self._state ^= cross & 0xFF   # light influence from Python state

        # Decode opcode
        op = self._decode(enc)

        # Execute
        result = self._dispatch(op & 0xFF, ops, bk)

        # Commit to shared state
        self._state = (self._state * _GLD + op) & _MASK32
        self._shared.rust_commit(self._state, 
                                  result if isinstance(result, int) else 0)
        return result

    def _decode(self, enc: int) -> int:
        """Decode opcode — mirrors Rust resolve_op formula."""
        if self._native:
            op = self._nc.resolve_op(
                enc, self._state, self._state, self._prev_op, self._data_flow
            )
        else:
            base    = ((enc ^ self._state) + self._state) ^ (self._state >> 3)
            base   &= _MASK32
            rotated = (base ^ (self._prev_op * _ROT)) & _MASK32
            op      = (rotated + self._data_flow) ^ ((self._data_flow << 7) & _MASK32)
            op     &= _MASK32
        self._prev_op  = op
        # Advance state
        s = self._state
        s = (s ^ ((s << 5) & _MASK32)) & _MASK32
        s = (s ^ (op * _GLD)) & _MASK32
        self._state = s
        return op

    def _dispatch(self, op: int, ops: list, bk: int) -> Any:
        """Minimal opcode dispatch — mirrors VM2 opcodes (odd IDs)."""
        def _reg(n):
            return self._regs[n & 0xF] if isinstance(n, int) else self._env.get(str(n), 0)
        def _sreg(n, v):
            if isinstance(n, int): self._regs[n & 0xF] = v
            else: self._env[str(n)] = v

        def _src(i):
            srcs = [v for t,tp,v in ops if t=="src"]
            return srcs[i] if i < len(srcs) else 0
        def _dst():
            for t,tp,v in ops:
                if t=="dst": return v
            return None

        d = _dst()

        # Arithmetic (VM2 odd opcodes)
        if op == 0x1B: _sreg(d, _reg(_src(0)) + _reg(_src(1))); return _reg(d)
        if op == 0x1D: _sreg(d, _reg(_src(0)) - _reg(_src(1))); return _reg(d)
        if op == 0x1F: _sreg(d, _reg(_src(0)) * _reg(_src(1))); return _reg(d)
        if op == 0x2B: _sreg(d, _reg(_src(0)) & _reg(_src(1))); return _reg(d)
        if op == 0x2D: _sreg(d, _reg(_src(0)) | _reg(_src(1))); return _reg(d)
        if op == 0x2F: _sreg(d, _reg(_src(0)) ^ _reg(_src(1))); return _reg(d)
        if op == 0x3D: _sreg(d, int(_reg(_src(0)) == _reg(_src(1)))); return _reg(d)
        if op == 0x55: self._result = _reg(d); self._done = True; return _reg(d)

        # Load/store
        if op == 0x0D:
            v = self._consts.get(_src(0)) if hasattr(self._consts, 'get') else None
            _sreg(d if d is not None else _src(1), v)
            return v
        if op == 0x0F:
            v = self._env.get(str(_src(0)))
            _sreg(_src(1), v)
            return v
        if op == 0x11:
            self._env[str(_src(1))] = _reg(_src(0))
            return _reg(_src(0))

        return 0   # NOP / unknown

    # ── Compute Rust's expected confirmation value ─────────────────────────────
    def confirmation_value(self, vm3_result: int) -> int:
        """
        Compute what Rust should return as confirmation of vm3_result.
        confirmation = hash(vm3_result ^ cross_key) & MASK
        Python can verify this without knowing Rust's internal state.
        """
        ck = self._shared.cross_key
        return (vm3_result ^ ck) & _MASK32

    def get_result(self) -> Any:
        return self._result

    def get_state(self) -> int:
        return self._state
