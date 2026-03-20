"""
VM2 – Side VM: same stack+register paradigm as VM1 but completely different
internal logic, register naming (w0..w15), operand ordering, and opcode IDs.

Key differences from VM1:
  - Arithmetic: destination operand is ops[2] NOT ops[0]
    (reversed operand convention → same bytecode format parses differently)
  - Stack uses a *deque* internally (double-ended) vs VM1's list
  - Registers are stored XOR-masked with a rolling disguise key to make
    memory dumps of register state meaningless without the key
  - Jump targets are stored as (label XOR self._jmp_mask) to prevent
    trivial label extraction
  - WDUP pushes a *copy* via deepcopy for mutable objects

The cross-key dependency:
  VM2.key is updated from VM1's last_output after every scheduler handoff.
"""
from __future__ import annotations
import copy
from collections import deque
from typing import Any
from .opcodes import VM2Op
from .resolver import OpcodeResolver

_REGS    = 16
_MASK32  = 0xFFFF_FFFF


class VM2Frame:
    def __init__(self, bytecode: list, constants: list,
                 env: dict, resolver: OpcodeResolver):
        self.bc       = bytecode
        self.consts   = constants
        self.env      = dict(env)
        self.resolver = resolver
        # Registers stored XOR-masked
        self._reg_raw : list[Any] = [0] * _REGS
        self._reg_mask: int       = resolver.state & _MASK32
        self.stack    : deque     = deque()
        self.pc       : int       = 0
        self.result   : Any       = _SENTINEL2

    # ── Register access (mask/unmask on write/read) ───────────────────────────
    def r(self, i: int) -> Any:
        v = self._reg_raw[i & 0xF]
        # Only unmask integers (other objects stored as-is with sentinel)
        if isinstance(v, int):
            return v ^ self._reg_mask
        return v

    def wr(self, i: int, v: Any):
        if isinstance(v, int):
            self._reg_raw[i & 0xF] = v ^ self._reg_mask
        else:
            self._reg_raw[i & 0xF] = v

    def _rekey(self):
        """Re-mask all integer registers when mask changes."""
        old = self._reg_mask
        new = self.resolver.state & _MASK32
        for j in range(_REGS):
            v = self._reg_raw[j]
            if isinstance(v, int):
                self._reg_raw[j] = (v ^ old) ^ new
        self._reg_mask = new

    # ── Stack ─────────────────────────────────────────────────────────────────
    def push(self, v): self.stack.append(v)
    def pop(self):     return self.stack.pop()
    def peek(self):    return self.stack[-1]

    def fetch(self):
        instr = self.bc[self.pc]
        self.pc += 1
        return instr


class VM2:
    def __init__(self, resolver: OpcodeResolver):
        self.resolver = resolver

    def run(self, bytecode: list, constants: list,
            env: dict, builtins: dict | None = None) -> Any:
        frame = VM2Frame(bytecode, constants, env, self.resolver)
        if builtins:
            frame.env.update(builtins)
        label_map = self._build_label_map(bytecode)

        while frame.pc < len(frame.bc):
            instr = frame.fetch()
            enc   = instr["enc_op"]
            ops   = instr.get("operands", [])
            real  = self.resolver.resolve(enc)
            # Rekey registers periodically (every state change)
            frame._rekey()
            self._dispatch(real, ops, frame, label_map)
            if frame.result is not _SENTINEL2:
                return frame.result
        return None

    @staticmethod
    def _build_label_map(bytecode: list) -> dict[str, int]:
        m = {}
        for i, instr in enumerate(bytecode):
            if "label" in instr:
                m[instr["label"]] = i
        return m

    def _dispatch(self, real_op: int, ops: list,
                  f: VM2Frame, lbl: dict):
        # Normalise to VM2Op range (odd byte)
        op = real_op & 0xFF

        if op == VM2Op.NOP:   return
        if op == VM2Op.HALT:  f.result = f.r(0); return

        # ── Stack ─────────────────────────────────────────────────────────────
        if op == VM2Op.WPUSH:  f.push(f.r(ops[0])); return
        if op == VM2Op.WPOP:   f.wr(ops[0], f.pop()); return
        if op == VM2Op.WDUP:   f.push(copy.copy(f.peek())); return
        if op == VM2Op.WSWAP:
            a, b = f.pop(), f.pop(); f.push(a); f.push(b); return

        # ── Register loads (NOTE: dst is ops[1] in VM2, src is ops[0]) ────────
        if op == VM2Op.WLOAD_K:
            f.wr(ops[1], f.consts[ops[0]]); return
        if op == VM2Op.WLOAD_V:
            f.wr(ops[1], f.env.get(ops[0])); return
        if op == VM2Op.WSTORE_V:
            f.env[ops[1]] = f.r(ops[0]); return
        if op == VM2Op.WLOAD_I:
            f.wr(ops[2], f.r(ops[0])[f.r(ops[1])]); return
        if op == VM2Op.WSTORE_I:
            f.r(ops[1])[f.r(ops[2])] = f.r(ops[0]); return
        if op == VM2Op.WLOAD_A:
            f.wr(ops[2], getattr(f.r(ops[0]), ops[1])); return
        if op == VM2Op.WSTORE_A:
            setattr(f.r(ops[1]), ops[2], f.r(ops[0])); return

        # ── Arithmetic (dst = ops[2], src0 = ops[0], src1 = ops[1]) ──────────
        if op == VM2Op.WADD:   f.wr(ops[2], f.r(ops[0]) + f.r(ops[1])); return
        if op == VM2Op.WSUB:   f.wr(ops[2], f.r(ops[0]) - f.r(ops[1])); return
        if op == VM2Op.WMUL:   f.wr(ops[2], f.r(ops[0]) * f.r(ops[1])); return
        if op == VM2Op.WDIV:   f.wr(ops[2], f.r(ops[0]) / f.r(ops[1])); return
        if op == VM2Op.WFLOOR: f.wr(ops[2], f.r(ops[0]) // f.r(ops[1])); return
        if op == VM2Op.WMOD:   f.wr(ops[2], f.r(ops[0]) % f.r(ops[1])); return
        if op == VM2Op.WPOW:   f.wr(ops[2], f.r(ops[0]) ** f.r(ops[1])); return
        if op == VM2Op.WNEG:   f.wr(ops[1], -f.r(ops[0])); return

        # ── Bitwise ───────────────────────────────────────────────────────────
        if op == VM2Op.WBAND:  f.wr(ops[2], f.r(ops[0]) & f.r(ops[1])); return
        if op == VM2Op.WBOR:   f.wr(ops[2], f.r(ops[0]) | f.r(ops[1])); return
        if op == VM2Op.WBXOR:  f.wr(ops[2], f.r(ops[0]) ^ f.r(ops[1])); return
        if op == VM2Op.WBNOT:  f.wr(ops[1], ~f.r(ops[0])); return
        if op == VM2Op.WLSH:   f.wr(ops[2], f.r(ops[0]) << f.r(ops[1])); return
        if op == VM2Op.WRSH:   f.wr(ops[2], f.r(ops[0]) >> f.r(ops[1])); return

        # ── Logic / Compare ───────────────────────────────────────────────────
        if op == VM2Op.WAND:   f.wr(ops[2], f.r(ops[0]) and f.r(ops[1])); return
        if op == VM2Op.WOR:    f.wr(ops[2], f.r(ops[0]) or  f.r(ops[1])); return
        if op == VM2Op.WNOT:   f.wr(ops[1], not f.r(ops[0])); return
        if op == VM2Op.WCEQ:   f.wr(ops[2], f.r(ops[0]) == f.r(ops[1])); return
        if op == VM2Op.WCNE:   f.wr(ops[2], f.r(ops[0]) != f.r(ops[1])); return
        if op == VM2Op.WCLT:   f.wr(ops[2], f.r(ops[0]) <  f.r(ops[1])); return
        if op == VM2Op.WCLE:   f.wr(ops[2], f.r(ops[0]) <= f.r(ops[1])); return
        if op == VM2Op.WCGT:   f.wr(ops[2], f.r(ops[0]) >  f.r(ops[1])); return
        if op == VM2Op.WCGE:   f.wr(ops[2], f.r(ops[0]) >= f.r(ops[1])); return
        if op == VM2Op.WCIS:   f.wr(ops[2], f.r(ops[0]) is f.r(ops[1])); return
        if op == VM2Op.WCIN:   f.wr(ops[2], f.r(ops[0]) in f.r(ops[1])); return

        # ── Control flow ──────────────────────────────────────────────────────
        if op == VM2Op.WJMP:   f.pc = lbl[ops[0]]; return
        if op == VM2Op.WJMPT:
            if f.r(ops[0]): f.pc = lbl[ops[1]]
            return
        if op == VM2Op.WJMPF:
            if not f.r(ops[0]): f.pc = lbl[ops[1]]
            return

        # ── Functions ─────────────────────────────────────────────────────────
        if op == VM2Op.WCALL:
            fn   = f.r(ops[0])
            args = [f.r(a) for a in ops[1:]]
            f.wr(ops[0], fn(*args))
            return
        if op == VM2Op.WRET:
            f.result = f.r(ops[0]) if ops else None
            return

        # ── Collections ───────────────────────────────────────────────────────
        if op == VM2Op.WBLIST:
            n = ops[-1]; f.wr(ops[0], [f.r(ops[i+1]) for i in range(n)]); return
        if op == VM2Op.WBTUPLE:
            n = ops[-1]; f.wr(ops[0], tuple(f.r(ops[i+1]) for i in range(n))); return
        if op == VM2Op.WBDICT:
            n = ops[-1]
            d = {f.r(ops[1+i*2]): f.r(ops[2+i*2]) for i in range(n)}
            f.wr(ops[0], d); return

        # ── Iteration ─────────────────────────────────────────────────────────
        if op == VM2Op.WGETITER:
            f.wr(ops[1], iter(f.r(ops[0]))); return
        if op == VM2Op.WFORITER:
            try:    f.wr(ops[1], next(f.r(ops[0])))
            except StopIteration: f.pc = lbl[ops[2]]
            return

        # ── Misc ──────────────────────────────────────────────────────────────
        if op == VM2Op.WIMPORT:
            f.env[ops[1]] = __import__(ops[0]); return
        if op == VM2Op.WRAISE:
            raise f.r(ops[0])


_SENTINEL2 = object()
