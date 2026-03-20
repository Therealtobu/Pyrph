"""
ControlFlowRewriter – mutates IRModule's CFG structure to defeat static analysis.

Transforms applied:
  1. Block splitting – split each large block into 2 at a random midpoint,
     connected by an unconditional JUMP.  This inflates the block count
     and makes dominator trees wider.

  2. Fake edge injection – add JUMP_IF_FALSE edges to fake "dead" blocks
     using opaque-true conditions (the false branch is never taken).

  3. Goto trampoline – replace direct JUMP X with
         JUMP trampoline_X  ;  trampoline_X: JUMP X
     making indirect chains that look like non-trivial dispatch.

  4. Split RETURN into a STORE to a shared result register + JUMP to a
     single epilogue block that does the actual RETURN.
"""
from __future__ import annotations
import random
from ir.nodes import (
    IROp, IROperand, IRInstruction, IRBlock, IRFunction, IRModule
)
from .ir_obf_utils import make_fake, new_tmp, rand_key

_REG   = lambda n: IROperand("reg",   n)
_CONST = lambda v: IROperand("const", v)
_LBL   = lambda l: IROperand("label", l)

_SPLIT_PROB     = 0.55
_FAKE_EDGE_PROB = 0.40
_TRAMP_PROB     = 0.50


class ControlFlowRewriter:

    def run(self, module: IRModule, cfg=None) -> IRModule:
        for fn in module.functions:
            self._rewrite_fn(fn)
        return module

    def _rewrite_fn(self, fn: IRFunction):
        self._split_blocks(fn)
        self._inject_fake_edges(fn)
        self._add_trampolines(fn)
        self._unify_returns(fn)

    # ── 1. Block splitting ────────────────────────────────────────────────────
    def _split_blocks(self, fn: IRFunction):
        to_process = list(fn.blocks)  # snapshot
        for block in to_process:
            if random.random() > _SPLIT_PROB:
                continue
            instrs = block.instructions
            if len(instrs) < 4:
                continue
            mid = random.randint(2, len(instrs) - 2)

            new_blk = fn.new_block(block.label + "_split")
            new_blk.instructions = instrs[mid:]
            new_blk.successors   = block.successors
            new_blk.predecessors = [block.id]

            # Fix successor predecessor lists
            id_map = {b.id: b for b in fn.blocks}
            for sid in block.successors:
                succ = id_map.get(sid)
                if succ:
                    if block.id in succ.predecessors:
                        succ.predecessors.remove(block.id)
                    if new_blk.id not in succ.predecessors:
                        succ.predecessors.append(new_blk.id)

            block.instructions = instrs[:mid]
            block.instructions.append(_jump(new_blk.label))
            block.successors   = [new_blk.id]

    # ── 2. Fake edge injection ────────────────────────────────────────────────
    def _inject_fake_edges(self, fn: IRFunction):
        for block in list(fn.blocks):
            if random.random() > _FAKE_EDGE_PROB:
                continue
            dead_blk = fn.new_block(block.label + "_dead")
            dead_blk.instructions = [
                make_fake(fn),
                _jump("__never_" + dead_blk.label),
            ]
            # Insert JUMP_IF_FALSE before the block's last terminator
            instrs = block.instructions
            term_ops = {IROp.JUMP, IROp.JUMP_IF_TRUE, IROp.JUMP_IF_FALSE, IROp.RETURN}
            split_idx = len(instrs)
            for i, ins in enumerate(instrs):
                if ins.op in term_ops:
                    split_idx = i
                    break
            # Opaque-true condition: (id(object) & 1) == (id(object) & 1)
            cond_reg = new_tmp(fn)
            opaque_true = IRInstruction(
                op=IROp.LOAD_CONST,
                dst=_REG(cond_reg),
                src=[_CONST(1)],
                metadata={"opaque_pred": True},
            )
            # JUMP_IF_FALSE cond → dead (never executes)
            fake_branch = IRInstruction(
                op=IROp.JUMP_IF_FALSE,
                src=[_REG(cond_reg)],
                label=dead_blk.label,
                metadata={"dead_edge": True},
            )
            block.instructions = (
                instrs[:split_idx] + [opaque_true, fake_branch] + instrs[split_idx:]
            )
            if dead_blk.id not in block.successors:
                block.successors.append(dead_blk.id)
            dead_blk.predecessors.append(block.id)

    # ── 3. Trampoline insertion ───────────────────────────────────────────────
    def _add_trampolines(self, fn: IRFunction):
        for block in list(fn.blocks):
            new_instrs = []
            for instr in block.instructions:
                if instr.op == IROp.JUMP and random.random() < _TRAMP_PROB:
                    original_label = instr.label
                    tramp = fn.new_block("tramp_" + str(len(fn.blocks)))
                    tramp.instructions = [_jump(original_label)]
                    instr = IRInstruction(
                        op=IROp.JUMP, label=tramp.label,
                        metadata={"trampoline": True},
                    )
                new_instrs.append(instr)
            block.instructions = new_instrs

    # ── 4. Unified return epilogue ────────────────────────────────────────────
    def _unify_returns(self, fn: IRFunction):
        # Find blocks that end with RETURN
        ret_blocks = [
            b for b in fn.blocks
            if b.instructions and b.instructions[-1].op == IROp.RETURN
        ]
        if len(ret_blocks) <= 1:
            return

        ret_reg  = new_tmp(fn)
        epilogue = fn.new_block("__epilogue")
        epilogue.instructions = [
            IRInstruction(op=IROp.RETURN, src=[_REG(ret_reg)])
        ]

        for b in ret_blocks:
            ret_instr = b.instructions[-1]
            # Replace RETURN with STORE + JUMP epilogue
            store = IRInstruction(
                op=IROp.STORE_VAR,
                src=(ret_instr.src or [_CONST(None)]) + [IROperand("var", ret_reg)],
            )
            b.instructions[-1] = store
            b.instructions.append(_jump(epilogue.label))
            if epilogue.id not in b.successors:
                b.successors.append(epilogue.id)
            epilogue.predecessors.append(b.id)


def _jump(label: str) -> IRInstruction:
    return IRInstruction(op=IROp.JUMP, label=label)
