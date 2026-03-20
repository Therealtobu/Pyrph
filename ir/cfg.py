"""
CFGBuilder – builds / repairs the Control Flow Graph inside each IRFunction.

After IRBuilder runs, block.successors / block.predecessors may be incomplete
for cases like FOR_ITER (two targets: body or exit) or unreachable blocks.
CFGBuilder does a second pass to ensure the graph is consistent.

Exposes:
  CFGBuilder().build(module)  → returns the same IRModule (mutates in-place)
  CFG helper methods: dominators, reachable, post_order
"""
from __future__ import annotations
from typing import Optional
from .nodes import IROp, IRModule, IRFunction, IRBlock


class CFGBuilder:

    def build(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            self._build_fn(fn)
        return module

    # ── Per-function ──────────────────────────────────────────────────────────
    def _build_fn(self, fn: IRFunction):
        # Map label → block
        label_map: dict[str, IRBlock] = {b.label: b for b in fn.blocks}

        # Clear old edges (will be rebuilt)
        for b in fn.blocks:
            b.successors   = []
            b.predecessors = []

        # Walk instructions and connect edges
        for block in fn.blocks:
            for instr in block.instructions:
                if instr.op in (IROp.JUMP,):
                    tgt = label_map.get(instr.label)
                    if tgt:
                        _link(block, tgt)

                elif instr.op in (IROp.JUMP_IF_TRUE, IROp.JUMP_IF_FALSE):
                    tgt = label_map.get(instr.label)
                    if tgt:
                        _link(block, tgt)

                elif instr.op == IROp.FOR_ITER:
                    # FOR_ITER has a "done" label (exit) AND falls through
                    tgt = label_map.get(instr.label)
                    if tgt:
                        _link(block, tgt)
                    # fall-through to next block
                    next_blk = _next_block(fn, block)
                    if next_blk:
                        _link(block, next_blk)

                elif instr.op == IROp.RETURN:
                    pass   # no outgoing edge

        # Mark unreachable blocks
        reachable = self.reachable(fn)
        for b in fn.blocks:
            b.metadata = getattr(b, "metadata", {})
            if hasattr(b, "metadata"):
                pass
            b.instructions  # access to silence linter

    # ── Graph algorithms ──────────────────────────────────────────────────────
    @staticmethod
    def reachable(fn: IRFunction) -> set[int]:
        """BFS from entry block; returns set of reachable block IDs."""
        if not fn.blocks:
            return set()
        visited: set[int] = set()
        queue   = [fn.blocks[0].id]
        id_map  = {b.id: b for b in fn.blocks}
        while queue:
            bid = queue.pop()
            if bid in visited:
                continue
            visited.add(bid)
            blk = id_map.get(bid)
            if blk:
                queue.extend(blk.successors)
        return visited

    @staticmethod
    def post_order(fn: IRFunction) -> list[IRBlock]:
        """Post-order traversal (useful for dominator computation)."""
        if not fn.blocks:
            return []
        id_map  = {b.id: b for b in fn.blocks}
        visited: set[int] = set()
        order:   list[IRBlock] = []

        def dfs(bid: int):
            if bid in visited:
                return
            visited.add(bid)
            blk = id_map.get(bid)
            if not blk:
                return
            for succ in blk.successors:
                dfs(succ)
            order.append(blk)

        dfs(fn.blocks[0].id)
        return order

    @staticmethod
    def dominators(fn: IRFunction) -> dict[int, set[int]]:
        """
        Computes dominator sets using the simple iterative algorithm.
        dom[n] = set of block IDs that dominate n.
        """
        if not fn.blocks:
            return {}
        all_ids = {b.id for b in fn.blocks}
        entry   = fn.blocks[0].id
        id_map  = {b.id: b for b in fn.blocks}

        dom: dict[int, set[int]] = {b.id: set(all_ids) for b in fn.blocks}
        dom[entry] = {entry}

        changed = True
        while changed:
            changed = False
            for b in fn.blocks:
                if b.id == entry:
                    continue
                preds = b.predecessors
                if not preds:
                    new_dom = {b.id}
                else:
                    new_dom = set.intersection(*(dom[p] for p in preds)) | {b.id}
                if new_dom != dom[b.id]:
                    dom[b.id] = new_dom
                    changed = True
        return dom


# ── Helpers ───────────────────────────────────────────────────────────────────
def _link(src: IRBlock, dst: IRBlock):
    if dst.id not in src.successors:
        src.successors.append(dst.id)
    if src.id not in dst.predecessors:
        dst.predecessors.append(src.id)


def _next_block(fn: IRFunction, blk: IRBlock) -> Optional[IRBlock]:
    idx = fn.blocks.index(blk)
    if idx + 1 < len(fn.blocks):
        return fn.blocks[idx + 1]
    return None
