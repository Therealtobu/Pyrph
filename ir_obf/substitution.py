"""
InstructionSubstitutor – replaces IR opcodes with semantically equivalent
but more complex multi-instruction sequences.

Substitution table (examples):
  ADD(a,b)       → t1=BAND(a,b); t2=BOR(a,b); dst=ADD(t1,t2)
                   [ because (a&b)+(a|b) == a+b+0 … NO, use: a+b == (a^b)+(a&b)<<1 ]
                   correct: (a ^ b) + ((a & b) << 1)

  SUB(a,b)       → NEG(b) → ADD(a, neg_b)

  BAND(a,b)      → t=(a+b) - BOR(a,b)
  BOR(a,b)       → t=(a+b) - BAND(a,b)  …wait, recursive. Use: a|(b) = ~(~a & ~b)
  BXOR(a,b)      → BOR(a,b) - BAND(a,b)

  MUL(a, const)  → repeated ADD sequence (only for small consts)
  CMP_EQ(a,b)    → NOT(CMP_NE(a,b))

Each substitution is chosen randomly with probability _PROB so code
doesn't expand uniformly (makes pattern-matching harder).
"""
from __future__ import annotations
import random
from .ir_obf_utils import new_tmp
from ..ir.nodes import IROp, IROperand, IRInstruction, IRModule, IRFunction, IRBlock

_PROB = 0.65   # probability any eligible instruction gets substituted
_REG  = lambda n: IROperand("reg", n)


class InstructionSubstitutor:

    def run(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            for block in fn.blocks:
                block.instructions = self._sub_block(block.instructions, fn)
        return module

    # ─────────────────────────────────────────────────────────────────────────
    def _sub_block(self, instrs: list[IRInstruction],
                   fn: IRFunction) -> list[IRInstruction]:
        out: list[IRInstruction] = []
        for instr in instrs:
            if random.random() < _PROB:
                expanded = self._substitute(instr, fn)
                out.extend(expanded)
            else:
                out.append(instr)
        return out

    def _substitute(self, instr: IRInstruction,
                    fn: IRFunction) -> list[IRInstruction]:
        op  = instr.op
        dst = instr.dst
        src = instr.src

        # ── ADD(a, b) → (a^b) + ((a&b) << 1) ────────────────────────────────
        if op == IROp.ADD and len(src) == 2:
            t1, t2, t3 = new_tmp(fn), new_tmp(fn), new_tmp(fn)
            return [
                _mk(IROp.BXOR,   _REG(t1), src),
                _mk(IROp.BAND,   _REG(t2), src),
                _mk(IROp.LSHIFT, _REG(t3), [_REG(t2), IROperand("const", 1)]),
                _mk(IROp.ADD,    dst,       [_REG(t1), _REG(t3)]),
            ]

        # ── SUB(a, b) → ADD(a, NEG(b)) ───────────────────────────────────────
        if op == IROp.SUB and len(src) == 2:
            t1 = new_tmp(fn)
            return [
                _mk(IROp.NEG, _REG(t1), [src[1]]),
                _mk(IROp.ADD, dst,       [src[0], _REG(t1)]),
            ]

        # ── BAND(a,b) → (a+b) - BOR(a,b) ────────────────────────────────────
        if op == IROp.BAND and len(src) == 2:
            t1, t2 = new_tmp(fn), new_tmp(fn)
            return [
                _mk(IROp.ADD, _REG(t1), src),
                _mk(IROp.BOR, _REG(t2), src),
                _mk(IROp.SUB, dst,       [_REG(t1), _REG(t2)]),
            ]

        # ── BXOR(a,b) → BOR(a,b) - BAND(a,b) ────────────────────────────────
        if op == IROp.BXOR and len(src) == 2:
            t1, t2 = new_tmp(fn), new_tmp(fn)
            return [
                _mk(IROp.BOR,  _REG(t1), src),
                _mk(IROp.BAND, _REG(t2), src),
                _mk(IROp.SUB,  dst,       [_REG(t1), _REG(t2)]),
            ]

        # ── CMP_EQ(a,b) → NOT(CMP_NE(a,b)) ──────────────────────────────────
        if op == IROp.CMP_EQ and len(src) == 2:
            t1 = new_tmp(fn)
            return [
                _mk(IROp.CMP_NE, _REG(t1), src),
                _mk(IROp.NOT,    dst,       [_REG(t1)]),
            ]

        # ── NEG(a) → BXOR(a, -1) + ADD(result, 1) [two's complement] ─────────
        if op == IROp.NEG and len(src) == 1:
            t1 = new_tmp(fn)
            return [
                _mk(IROp.BXOR, _REG(t1), [src[0], IROperand("const", -1)]),
                _mk(IROp.ADD,  dst,       [_REG(t1), IROperand("const", 1)]),
            ]

        return [instr]   # no substitution


# ── Helpers ───────────────────────────────────────────────────────────────────
def _mk(op: IROp, dst: IROperand | None, src: list[IROperand]) -> IRInstruction:
    instr = IRInstruction(op=op, dst=dst, src=list(src))
    return instr
