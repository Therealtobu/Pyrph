"""
VariantGenerator – clone một IRFunction thành N semantically-equivalent variants.

Mỗi variant nhận một permutation khác nhau của các micro-transforms:
  T0: RegisterRenamer   – đổi tên tất cả temp registers
  T1: ConstantSplitter  – split LOAD_CONST thành ADD(a, b) where a+b = const
  T2: NOPPadder         – chèn NOP clusters ngẫu nhiên
  T3: BlockDuplicator   – duplicate dead blocks với junk instructions
  T4: OperandFlipMBA    – flip operand order ở commutative ops (ADD, MUL, BAND...)
  T5: ChainedAssign     – x = val → tmp = val; x = tmp

N = 3 variants mặc định (configurable).
Mỗi variant dùng permutation khác nhau của T0..T5.

Dispatch function:
    def __dispatch_<fname>(variant_id, *args, **kwargs):
        vid = hash((variant_id, args)) % N
        return [v0, v1, v2][vid](*args, **kwargs)
"""
from __future__ import annotations
import copy
import itertools
import random
from dataclasses import dataclass, field
from typing import Callable

from ..ir.nodes import (
    IROp, IROperand, IRInstruction, IRBlock,
    IRFunction, IRModule,
)

_MASK32  = 0xFFFF_FFFF
_N_VARIANTS = 3

_REG   = lambda n: IROperand("reg",   n)
_VAR   = lambda n: IROperand("var",   n)
_CONST = lambda v: IROperand("const", v)

# Commutative ops where swapping src[0]/src[1] is safe
_COMMUTATIVE = {IROp.ADD, IROp.MUL, IROp.BAND, IROp.BOR,
                IROp.BXOR, IROp.AND, IROp.OR,
                IROp.CMP_EQ, IROp.CMP_NE}


# ── Micro-transforms ──────────────────────────────────────────────────────────

class RegisterRenamer:
    """Rename all __tN temp registers to __vN (different namespace)."""
    name = "reg_rename"

    def apply(self, fn: IRFunction) -> IRFunction:
        mapping: dict[str, str] = {}
        ctr = itertools.count(1)

        def _rename(op: IROperand) -> IROperand:
            if op.kind == "reg" and str(op.value).startswith("__t"):
                old = str(op.value)
                if old not in mapping:
                    mapping[old] = f"__v{next(ctr)}"
                return IROperand("reg", mapping[old])
            return op

        for block in fn.blocks:
            for instr in block.instructions:
                instr.dst = _rename(instr.dst) if instr.dst else None
                instr.src = [_rename(s) for s in instr.src]
        return fn


class ConstantSplitter:
    """
    LOAD_CONST(dst, const_ref(n)) where n is integer
    → tmp = n//2, dst = tmp + (n - n//2)
    """
    name = "const_split"

    def apply(self, fn: IRFunction) -> IRFunction:
        for block in fn.blocks:
            new_instrs: list[IRInstruction] = []
            for instr in block.instructions:
                if (instr.op == IROp.LOAD_CONST
                        and instr.dst
                        and len(instr.src) == 1
                        and instr.src[0].kind == "const"
                        and isinstance(instr.src[0].value, int)
                        and not isinstance(instr.src[0].value, bool)
                        and random.random() < 0.5):
                    n   = instr.src[0].value
                    a   = n // 2
                    b   = n - a
                    tmp = fn.new_temp()
                    load_a = IRInstruction(
                        op=IROp.LOAD_CONST,
                        dst=_REG(tmp),
                        src=[_CONST(a)],
                    )
                    add = IRInstruction(
                        op=IROp.ADD,
                        dst=instr.dst,
                        src=[_REG(tmp), _CONST(b)],
                    )
                    new_instrs.extend([load_a, add])
                else:
                    new_instrs.append(instr)
            block.instructions = new_instrs
        return fn


class NOPPadder:
    """Insert clusters of NOP instructions at random positions."""
    name = "nop_pad"

    def apply(self, fn: IRFunction) -> IRFunction:
        for block in fn.blocks:
            new_instrs: list[IRInstruction] = []
            for instr in block.instructions:
                if random.random() < 0.25:
                    n_nops = random.randint(1, 3)
                    for _ in range(n_nops):
                        new_instrs.append(IRInstruction(op=IROp.NOP))
                new_instrs.append(instr)
            block.instructions = new_instrs
        return fn


class BlockDuplicator:
    """
    For each block, create a dead clone with junk ops appended.
    The clone is unreachable but exists in the function's block list
    → confuses CFG reconstruction.
    """
    name = "block_dup"
    _ctr = itertools.count(1)

    def apply(self, fn: IRFunction) -> IRFunction:
        original_blocks = list(fn.blocks)
        for block in original_blocks:
            if len(block.instructions) < 2:
                continue
            if random.random() < 0.40:
                clone = IRBlock(
                    id    = len(fn.blocks),
                    label = f"__dead_{next(self._ctr)}",
                )
                # Copy instructions but corrupt constants
                for instr in block.instructions[:3]:
                    fake = copy.deepcopy(instr)
                    for op in fake.src:
                        if op.kind == "const" and isinstance(op.value, int):
                            op.value = op.value ^ random.randint(1, 0xFF)
                    clone.instructions.append(fake)
                clone.instructions.append(
                    IRInstruction(op=IROp.NOP, metadata={"dead_clone": True})
                )
                fn.blocks.append(clone)
        return fn


class OperandFlipMBA:
    """For commutative ops, randomly swap src[0] and src[1]."""
    name = "operand_flip"

    def apply(self, fn: IRFunction) -> IRFunction:
        for block in fn.blocks:
            for instr in block.instructions:
                if (instr.op in _COMMUTATIVE
                        and len(instr.src) >= 2
                        and random.random() < 0.50):
                    instr.src[0], instr.src[1] = instr.src[1], instr.src[0]
        return fn


class ChainedAssign:
    """
    STORE_VAR x ← r  →  STORE_VAR __chain_N ← r ; STORE_VAR x ← __chain_N
    """
    name = "chained_assign"
    _ctr = itertools.count(1)

    def apply(self, fn: IRFunction) -> IRFunction:
        for block in fn.blocks:
            new_instrs: list[IRInstruction] = []
            for instr in block.instructions:
                if (instr.op == IROp.STORE_VAR
                        and len(instr.src) >= 2
                        and random.random() < 0.35):
                    chain_name = f"__ch_{next(self._ctr)}"
                    mid = IRInstruction(
                        op  = IROp.STORE_VAR,
                        src = [instr.src[0], _VAR(chain_name)],
                    )
                    final = IRInstruction(
                        op  = IROp.STORE_VAR,
                        src = [_VAR(chain_name), instr.src[1]],
                    )
                    new_instrs.extend([mid, final])
                else:
                    new_instrs.append(instr)
            block.instructions = new_instrs
        return fn


_ALL_TRANSFORMS = [
    RegisterRenamer,
    ConstantSplitter,
    NOPPadder,
    BlockDuplicator,
    OperandFlipMBA,
    ChainedAssign,
]


# ── VariantGenerator ──────────────────────────────────────────────────────────

class VariantGenerator:
    """
    Produce N deep-copy variants of an IRFunction,
    each transformed with a different permutation of micro-transforms.
    """

    def __init__(self, n_variants: int = _N_VARIANTS):
        self.n = n_variants

    def generate(self, fn: IRFunction) -> list[IRFunction]:
        """Return list of N variant IRFunction objects."""
        variants: list[IRFunction] = []

        # Produce N different permutations of transforms
        perms = self._distinct_permutations(len(_ALL_TRANSFORMS), self.n)

        for i, perm in enumerate(perms):
            clone = self._deep_clone(fn, suffix=f"__var{i}")
            for tidx in perm:
                T = _ALL_TRANSFORMS[tidx]()
                T.apply(clone)
            variants.append(clone)

        return variants

    @staticmethod
    def _distinct_permutations(n_transforms: int, count: int) -> list[list[int]]:
        """Generate `count` distinct random permutations of transform indices."""
        all_idx  = list(range(n_transforms))
        seen     = set()
        result   = []
        attempts = 0
        while len(result) < count and attempts < 1000:
            attempts += 1
            perm = all_idx[:]
            random.shuffle(perm)
            # Take first 4 from each permutation to avoid too much inflation
            key = tuple(perm[:4])
            if key not in seen:
                seen.add(key)
                result.append(perm[:4])
        return result

    @staticmethod
    def _deep_clone(fn: IRFunction, suffix: str) -> IRFunction:
        """Deep copy an IRFunction with a new name."""
        clone        = IRFunction(name=fn.name + suffix, args=list(fn.args))
        clone._temps = fn._temps

        block_map: dict[int, IRBlock] = {}
        for block in fn.blocks:
            new_block = IRBlock(
                id    = block.id,
                label = block.label + suffix,
            )
            for instr in block.instructions:
                new_instr = IRInstruction(
                    op       = instr.op,
                    dst      = copy.deepcopy(instr.dst),
                    src      = [copy.deepcopy(s) for s in instr.src],
                    label    = (instr.label + suffix) if instr.label else None,
                    metadata = dict(instr.metadata),
                )
                if instr.enc_op is not None:
                    new_instr.enc_op = instr.enc_op
                new_block.instructions.append(new_instr)
            new_block.predecessors = list(block.predecessors)
            new_block.successors   = list(block.successors)
            clone.blocks.append(new_block)
            block_map[block.id] = new_block

        return clone
