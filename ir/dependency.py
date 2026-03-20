"""
DependencyAnalyzer – computes def-use chains and live-variable sets
for each IRFunction inside an IRModule.

Results are stored in each IRInstruction's metadata dict:
  instr.metadata["defs"]  = set of reg/var names defined by this instruction
  instr.metadata["uses"]  = set of reg/var names used by this instruction

Per-block liveness:
  block.metadata = {"live_in": set, "live_out": set}  (added here)

The dependency graph is also stored at function level and returned
as a plain dict for downstream IR-obf passes.
"""
from __future__ import annotations
from typing import Any
from .nodes import IROp, IRModule, IRFunction, IRBlock, IRInstruction, IROperand


# ── Operand helpers ───────────────────────────────────────────────────────────
def _op_names(ops: list[IROperand]) -> set[str]:
    """Extract variable/register names from a list of operands."""
    names: set[str] = set()
    for op in ops:
        if op.kind in ("reg", "var") and isinstance(op.value, str):
            names.add(op.value)
    return names


def _def_name(dst: IROperand | None) -> set[str]:
    if dst is None:
        return set()
    if dst.kind in ("reg", "var") and isinstance(dst.value, str):
        return {dst.value}
    return set()


class DependencyAnalyzer:

    def analyze(self, module: IRModule) -> dict:
        """
        Returns a module-level dependency summary:
          {
            fn_name: {
              "def_use":   {reg → [list of instrs that use it]},
              "use_def":   {reg → instr that defines it},
              "live_in":   {block_id → frozenset},
              "live_out":  {block_id → frozenset},
            },
            ...
          }
        """
        result = {}
        for fn in module.functions:
            result[fn.name] = self._analyze_fn(fn)
        return result

    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_fn(self, fn: IRFunction) -> dict:
        self._annotate_defs_uses(fn)
        live_in, live_out = self._liveness(fn)
        def_use, use_def  = self._build_chains(fn)

        # Store liveness on blocks so later passes can access it
        id_map = {b.id: b for b in fn.blocks}
        for bid, s in live_in.items():
            blk = id_map.get(bid)
            if blk:
                if not hasattr(blk, "meta"):
                    blk.meta = {}
                blk.meta["live_in"]  = frozenset(s)
                blk.meta["live_out"] = frozenset(live_out.get(bid, set()))

        return {
            "def_use":  def_use,
            "use_def":  use_def,
            "live_in":  {k: frozenset(v) for k, v in live_in.items()},
            "live_out": {k: frozenset(v) for k, v in live_out.items()},
        }

    # ── Step 1: annotate each instruction with defs / uses ────────────────────
    def _annotate_defs_uses(self, fn: IRFunction):
        for instr in fn.all_instructions():
            defs = _def_name(instr.dst)
            uses = _op_names(instr.src)
            # STORE_VAR: destination is in src[1]
            if instr.op == IROp.STORE_VAR and len(instr.src) >= 2:
                defs |= _def_name(instr.src[1])
                uses  = _op_names(instr.src[:1])
            instr.metadata["defs"] = defs
            instr.metadata["uses"] = uses

    # ── Step 2: backward dataflow liveness ────────────────────────────────────
    def _liveness(self, fn: IRFunction):
        id_map  = {b.id: b for b in fn.blocks}
        live_in:  dict[int, set] = {b.id: set() for b in fn.blocks}
        live_out: dict[int, set] = {b.id: set() for b in fn.blocks}

        # Compute gen/kill per block
        gen:  dict[int, set] = {}
        kill: dict[int, set] = {}
        for b in fn.blocks:
            g, k = set(), set()
            for instr in b.instructions:
                # uses not yet killed → gen
                g |= (instr.metadata.get("uses", set()) - k)
                # definitions → kill
                k |= instr.metadata.get("defs", set())
            gen[b.id]  = g
            kill[b.id] = k

        # Iterative backward analysis
        changed = True
        while changed:
            changed = False
            for b in reversed(fn.blocks):
                # live_out[b] = union of live_in[succ] for succ in successors
                new_out: set = set()
                for sid in b.successors:
                    succ = id_map.get(sid)
                    if succ:
                        new_out |= live_in[sid]
                # live_in[b] = gen[b] ∪ (live_out[b] − kill[b])
                new_in = gen[b.id] | (new_out - kill[b.id])
                if new_in != live_in[b.id] or new_out != live_out[b.id]:
                    live_in[b.id]  = new_in
                    live_out[b.id] = new_out
                    changed = True

        return live_in, live_out

    # ── Step 3: def-use / use-def chains ─────────────────────────────────────
    def _build_chains(self, fn: IRFunction):
        def_use: dict[str, list[IRInstruction]] = {}   # definer → users
        use_def: dict[str, IRInstruction]        = {}   # user reg → definer

        for instr in fn.all_instructions():
            for d in instr.metadata.get("defs", set()):
                use_def[d] = instr
                if d not in def_use:
                    def_use[d] = []

            for u in instr.metadata.get("uses", set()):
                definer = use_def.get(u)
                if definer is not None:
                    def_use.setdefault(u, []).append(instr)

        return def_use, use_def
