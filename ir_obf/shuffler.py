"""
InstructionShuffler – reorders independent instructions within each block
and inserts a JUMP-TABLE dispatch header so the block entry point changes
per execution path, breaking linear disassembly reads.

Algorithm:
  1. Build a dependency DAG inside each block (instruction i depends on j
     if j defines something that i uses).
  2. Topological sort → produces a legal linearisation of the DAG.
  3. Randomise among all legal topological orderings using Kahn's algorithm
     with random tie-breaking.
  4. Prepend a fake dispatch label + LABEL instruction so the block appears
     to be entered via a computed jump (confuses static CFG reconstruction).
"""
from __future__ import annotations
import random
from collections import defaultdict, deque
from ..ir.nodes import IROp, IROperand, IRInstruction, IRBlock, IRModule
from .ir_obf_utils import make_fake, make_nop


class InstructionShuffler:

    def run(self, module: IRModule, cfg=None) -> IRModule:
        for fn in module.functions:
            for block in fn.blocks:
                block.instructions = self._shuffle_block(block, fn)
        return module

    # ─────────────────────────────────────────────────────────────────────────
    def _shuffle_block(self, block: IRBlock, fn) -> list[IRInstruction]:
        instrs = block.instructions
        if len(instrs) <= 2:
            return instrs

        # Separate terminators (keep at end)
        TERM_OPS = {IROp.JUMP, IROp.JUMP_IF_TRUE, IROp.JUMP_IF_FALSE,
                    IROp.RETURN, IROp.RAISE}
        body = [i for i in instrs if i.op not in TERM_OPS]
        term = [i for i in instrs if i.op in TERM_OPS]

        # Build dep DAG among body instructions
        dag  = self._build_dag(body)
        body = self._topo_shuffle(body, dag)

        # Inject 1-3 fake instructions at random positions
        n_fakes = random.randint(1, 3)
        for _ in range(n_fakes):
            pos = random.randint(0, len(body))
            body.insert(pos, make_fake(fn))

        # Prepend LABEL pseudo-instruction acting as dispatch anchor
        anchor = IRInstruction(
            op=IROp.LABEL,
            label=block.label + "_disp",
            metadata={"jump_table_anchor": True},
        )
        return [anchor] + body + term

    # ── Dependency DAG ────────────────────────────────────────────────────────
    @staticmethod
    def _build_dag(instrs: list[IRInstruction]) -> dict[int, set[int]]:
        """
        Returns adj: adj[i] = {j, ...} means j depends on i
        (i must execute before j).
        """
        # reg/var → last definer index
        last_def: dict[str, int] = {}
        adj: dict[int, set[int]] = defaultdict(set)
        in_deg: dict[int, int]   = {i: 0 for i in range(len(instrs))}

        def _def_names(instr):
            names = set()
            if instr.dst and instr.dst.kind in ("reg", "var"):
                names.add(str(instr.dst.value))
            if instr.op == IROp.STORE_VAR and len(instr.src) >= 2:
                names.add(str(instr.src[1].value))
            return names

        def _use_names(instr):
            names = set()
            for op in instr.src:
                if op.kind in ("reg", "var"):
                    names.add(str(op.value))
            return names

        for idx, instr in enumerate(instrs):
            for u in _use_names(instr):
                if u in last_def:
                    dep = last_def[u]
                    if dep != idx and idx not in adj[dep]:
                        adj[dep].add(idx)
                        in_deg[idx] += 1
            for d in _def_names(instr):
                last_def[d] = idx

        return dict(adj), in_deg   # type: ignore[return-value]

    @staticmethod
    def _topo_shuffle(instrs: list[IRInstruction],
                      dag_pair) -> list[IRInstruction]:
        adj, in_deg = dag_pair
        # Kahn's algorithm with random tie-breaking
        ready = deque(i for i in range(len(instrs)) if in_deg[i] == 0)
        order: list[int] = []
        while ready:
            # Pick random element from ready queue
            lst = list(ready)
            random.shuffle(lst)
            ready = deque(lst)
            idx = ready.popleft()
            order.append(idx)
            for succ in adj.get(idx, set()):
                in_deg[succ] -= 1
                if in_deg[succ] == 0:
                    ready.append(succ)

        # If cycle detected (shouldn't happen), preserve original
        if len(order) < len(instrs):
            return instrs
        return [instrs[i] for i in order]
