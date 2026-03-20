"""
VM1 – Inner VM: Stack + Register hybrid (strongest interpreter).

Architecture:
  - 16 general-purpose registers (r0 … r15)
  - Operand stack of unlimited depth
  - Environment dict (variable namespace)
  - Call stack for function frames
  - All arithmetic ops work on registers
  - SPUSH / SPOP bridge between stack and registers
  - This design forces attackers to understand BOTH stack and register
    semantics simultaneously.

Execution model:
  - Instruction stream: list of (enc_op, *operands)
  - OpcodeResolver decodes enc_op at runtime (no static map)
  - After each instruction, state is updated (resolver._advance)
"""
from __future__ import annotations
from typing import Any
from .opcodes import VM1Op
from .resolver import OpcodeResolver

_REGS = 16


class VM1Frame:
    def __init__(self, bytecode: list, constants: list,
                 env: dict, resolver: OpcodeResolver):
        self.bc       = bytecode
        self.consts   = constants
        self.env      = dict(env)
        self.resolver = resolver
        self.regs:  list[Any]     = [None] * _REGS
        self.stack: list[Any]     = []
        self.pc:    int           = 0
        self.result: Any          = None

    # ── helpers ───────────────────────────────────────────────────────────────
    def fetch(self):
        instr = self.bc[self.pc]
        self.pc += 1
        return instr

    def push(self, v): self.stack.append(v)
    def pop(self):     return self.stack.pop()
    def peek(self):    return self.stack[-1]

    def r(self, i):         return self.regs[i & 0xF]
    def wr(self, i, v):     self.regs[i & 0xF] = v


class VM1:
    """
    Executes a VM1 bytecode stream.
    bytecode: list of dicts with keys enc_op, operands (list of raw values),
              and optionally label (str) for jump resolution.
    """

    def __init__(self, resolver: OpcodeResolver):
        self.resolver = resolver

    def run(self, bytecode: list, constants: list,
            env: dict, builtins: dict | None = None) -> Any:
        frame = VM1Frame(bytecode, constants, env, self.resolver)
        if builtins:
            frame.env.update(builtins)

        label_map = self._build_label_map(bytecode)

        while frame.pc < len(frame.bc):
            instr = frame.fetch()
            enc   = instr["enc_op"]
            ops   = instr.get("operands", [])
            real  = self.resolver.resolve(enc)
            self._dispatch(real, ops, frame, label_map)

            if frame.result is not _SENTINEL:
                return frame.result

        return None

    # ── Label map ─────────────────────────────────────────────────────────────
    @staticmethod
    def _build_label_map(bytecode: list) -> dict[str, int]:
        m = {}
        for i, instr in enumerate(bytecode):
            if "label" in instr:
                m[instr["label"]] = i
        return m

    # ── Dispatch ──────────────────────────────────────────────────────────────
    def _dispatch(self, real_op: int, ops: list,
                  f: VM1Frame, lbl: dict):
        op = real_op & 0xFF   # normalise to low byte for VM1Op range

        # ── NOP / HALT ────────────────────────────────────────────────────────
        if op == VM1Op.NOP:    return
        if op == VM1Op.HALT:   f.result = f.r(0); return

        # ── Stack ─────────────────────────────────────────────────────────────
        if op == VM1Op.SPUSH:  f.push(f.r(ops[0])); return
        if op == VM1Op.SPOP:   f.wr(ops[0], f.pop()); return
        if op == VM1Op.SDUP:   f.push(f.peek()); return
        if op == VM1Op.SSWAP:
            a, b = f.pop(), f.pop(); f.push(a); f.push(b); return

        # ── Register loads ────────────────────────────────────────────────────
        if op == VM1Op.RLOAD_CONST:
            f.wr(ops[0], f.consts[ops[1]]); return
        if op == VM1Op.RLOAD_VAR:
            f.wr(ops[0], f.env.get(ops[1])); return
        if op == VM1Op.RSTORE_VAR:
            f.env[ops[1]] = f.r(ops[0]); return
        if op == VM1Op.RLOAD_IDX:
            f.wr(ops[0], f.r(ops[1])[f.r(ops[2])]); return
        if op == VM1Op.RSTORE_IDX:
            f.r(ops[0])[f.r(ops[1])] = f.r(ops[2]); return
        if op == VM1Op.RLOAD_ATTR:
            f.wr(ops[0], getattr(f.r(ops[1]), ops[2])); return
        if op == VM1Op.RSTORE_ATTR:
            setattr(f.r(ops[0]), ops[2], f.r(ops[1])); return

        # ── Arithmetic ────────────────────────────────────────────────────────
        if op == VM1Op.RADD:   f.wr(ops[0], f.r(ops[1]) + f.r(ops[2])); return
        if op == VM1Op.RSUB:   f.wr(ops[0], f.r(ops[1]) - f.r(ops[2])); return
        if op == VM1Op.RMUL:   f.wr(ops[0], f.r(ops[1]) * f.r(ops[2])); return
        if op == VM1Op.RDIV:   f.wr(ops[0], f.r(ops[1]) / f.r(ops[2])); return
        if op == VM1Op.RFLOOR: f.wr(ops[0], f.r(ops[1]) // f.r(ops[2])); return
        if op == VM1Op.RMOD:   f.wr(ops[0], f.r(ops[1]) % f.r(ops[2])); return
        if op == VM1Op.RPOW:   f.wr(ops[0], f.r(ops[1]) ** f.r(ops[2])); return
        if op == VM1Op.RNEG:   f.wr(ops[0], -f.r(ops[1])); return

        # ── Bitwise ───────────────────────────────────────────────────────────
        if op == VM1Op.RBAND:  f.wr(ops[0], f.r(ops[1]) & f.r(ops[2])); return
        if op == VM1Op.RBOR:   f.wr(ops[0], f.r(ops[1]) | f.r(ops[2])); return
        if op == VM1Op.RBXOR:  f.wr(ops[0], f.r(ops[1]) ^ f.r(ops[2])); return
        if op == VM1Op.RBNOT:  f.wr(ops[0], ~f.r(ops[1])); return
        if op == VM1Op.RLSHIFT:f.wr(ops[0], f.r(ops[1]) << f.r(ops[2])); return
        if op == VM1Op.RRSHIFT:f.wr(ops[0], f.r(ops[1]) >> f.r(ops[2])); return

        # ── Logic / Compare ───────────────────────────────────────────────────
        if op == VM1Op.RAND:   f.wr(ops[0], f.r(ops[1]) and f.r(ops[2])); return
        if op == VM1Op.ROR:    f.wr(ops[0], f.r(ops[1]) or  f.r(ops[2])); return
        if op == VM1Op.RNOT_L: f.wr(ops[0], not f.r(ops[1])); return
        if op == VM1Op.RCEQ:   f.wr(ops[0], f.r(ops[1]) == f.r(ops[2])); return
        if op == VM1Op.RCNE:   f.wr(ops[0], f.r(ops[1]) != f.r(ops[2])); return
        if op == VM1Op.RCLT:   f.wr(ops[0], f.r(ops[1]) <  f.r(ops[2])); return
        if op == VM1Op.RCLE:   f.wr(ops[0], f.r(ops[1]) <= f.r(ops[2])); return
        if op == VM1Op.RCGT:   f.wr(ops[0], f.r(ops[1]) >  f.r(ops[2])); return
        if op == VM1Op.RCGE:   f.wr(ops[0], f.r(ops[1]) >= f.r(ops[2])); return
        if op == VM1Op.RCIS:   f.wr(ops[0], f.r(ops[1]) is f.r(ops[2])); return
        if op == VM1Op.RCIN:   f.wr(ops[0], f.r(ops[1]) in f.r(ops[2])); return

        # ── Control flow ──────────────────────────────────────────────────────
        if op == VM1Op.JMP:    f.pc = lbl[ops[0]]; return
        if op == VM1Op.JMPT:
            if f.r(ops[0]): f.pc = lbl[ops[1]]
            return
        if op == VM1Op.JMPF:
            if not f.r(ops[0]): f.pc = lbl[ops[1]]
            return

        # ── Functions ─────────────────────────────────────────────────────────
        if op == VM1Op.CALL:
            fn   = f.r(ops[0])
            args = [f.r(a) for a in ops[1:]]
            f.wr(ops[0], fn(*args))
            return
        if op == VM1Op.RET:
            f.result = f.r(ops[0]) if ops else None
            return

        # ── Collections ───────────────────────────────────────────────────────
        if op == VM1Op.BLIST:
            n = ops[-1]; f.wr(ops[0], [f.r(ops[i+1]) for i in range(n)]); return
        if op == VM1Op.BTUPLE:
            n = ops[-1]; f.wr(ops[0], tuple(f.r(ops[i+1]) for i in range(n))); return
        if op == VM1Op.BDICT:
            n = ops[-1]
            d = {f.r(ops[1 + i*2]): f.r(ops[2 + i*2]) for i in range(n)}
            f.wr(ops[0], d); return

        # ── Iteration ─────────────────────────────────────────────────────────
        if op == VM1Op.GETITER:
            f.wr(ops[0], iter(f.r(ops[1]))); return
        if op == VM1Op.FORITER:
            try:
                f.wr(ops[0], next(f.r(ops[1])))
            except StopIteration:
                f.pc = lbl[ops[2]]
            return

        # ── Misc ──────────────────────────────────────────────────────────────
        if op == VM1Op.IMPORT:
            f.env[ops[0]] = __import__(ops[1]); return
        if op == VM1Op.RAISE:
            raise f.r(ops[0])
        # Unknown op → NOP
        return


_SENTINEL = object()
VM1Frame.result = _SENTINEL   # type: ignore[attr-defined]
