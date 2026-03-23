"""Shared utilities for ir_obf passes."""
import random
from ..ir.nodes import IRFunction, IRInstruction, IROp, IROperand


def new_tmp(fn: IRFunction) -> str:
    return fn.new_temp()


def make_nop() -> IRInstruction:
    return IRInstruction(op=IROp.NOP)


def make_fake(fn: IRFunction) -> IRInstruction:
    """Returns a FAKE (dead) instruction that never affects real state."""
    t = new_tmp(fn)
    dead = IRInstruction(
        op=IROp.FAKE,
        dst=IROperand("reg", t),
        src=[IROperand("const", random.randint(0, 0xFFFF))],
        metadata={"dead": True},
    )
    return dead


def rand_key(bits: int = 32) -> int:
    return random.getrandbits(bits)
