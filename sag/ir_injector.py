"""
SAGIRInjector – rewrites IRModule instructions to use alias sets.

For each STORE_VAR x ← src:
  BEFORE:  STORE_VAR  x ← r1
  AFTER:
    SAG_DEFINE  x    ← [real_src, fake_a, fake_b]   (NOP + metadata)
    STORE_VAR   x    ← r1                            (original, kept)
    SAG_TICK    x                                     (mutate sag_state)
    STORE_VAR   __sag_a_x ← fake_a_expr              (decoy stores)
    STORE_VAR   __sag_b_x ← fake_b_expr

For each LOAD_VAR dst ← x:
  BEFORE:  LOAD_VAR   dst ← x
  AFTER:
    SAG_SELECT  __sag_idx_x ← sag_sel(key, n)        (pick alias)
    LOAD_VAR    __sag_real  ← x                       (real value)
    LOAD_VAR    __sag_fa    ← __sag_a_x               (fake values)
    LOAD_VAR    __sag_fb    ← __sag_b_x
    SAG_COMBINE dst ← (__sag_real, __sag_fa, __sag_fb, __sag_idx_x, key)

SAG_COMBINE at runtime:
    vals[idx] is the real value (idx = real_idx)
    others are mixed in via XOR fold then cancelled out by key
    → result = real value  (correct semantics preserved)

This preserves program correctness while making every read
appear to depend on multiple sources with dynamic selection.
"""
from __future__ import annotations
import itertools

from ..ir.nodes import (
    IROp, IROperand, IRInstruction, IRBlock,
    IRFunction, IRModule,
)
from .alias_node import (
    AliasSet, AliasGraph,
    SAG_DEFINE, SAG_SELECT, SAG_READ, SAG_COMBINE, SAG_RETIRE,
)

_ctr = itertools.count(1)

_REG  = lambda n: IROperand("reg",   n)
_VAR  = lambda n: IROperand("var",   n)
_CONST= lambda v: IROperand("const", v)


def _sag_alias_var(var: str, idx: int) -> str:
    return f"__sag_{idx}_{var}"

def _sag_idx_var(var: str) -> str:
    return f"__sag_idx_{var}"

def _sag_tick_instr(var: str) -> IRInstruction:
    return IRInstruction(
        op       = IROp.NOP,
        src      = [_VAR(var)],
        metadata = {"sag_op": "SAG_TICK", "var": var},
    )

def _sag_define_instr(alias_set: AliasSet) -> IRInstruction:
    src_ops = [s.operand for s in alias_set.sources]
    return IRInstruction(
        op       = IROp.NOP,
        dst      = _VAR(alias_set.var_name),
        src      = src_ops,
        metadata = {
            "sag_op":    SAG_DEFINE,
            "var":       alias_set.var_name,
            "real_idx":  alias_set.real_idx,
            "n":         alias_set.n_aliases(),
            "key":       alias_set.select_key,
        },
    )

def _sag_combine_instr(dst: IROperand,
                       alias_set: AliasSet,
                       tmp_regs: list[str]) -> IRInstruction:
    return IRInstruction(
        op       = IROp.NOP,
        dst      = dst,
        src      = [_REG(r) for r in tmp_regs],
        metadata = {
            "sag_op":   SAG_COMBINE,
            "real_idx": alias_set.real_idx,
            "key":      alias_set.select_key,
            "n":        alias_set.n_aliases(),
        },
    )


class SAGIRInjector:
    """
    Rewrites IR instructions to embed alias sets.
    Called once per IRModule after AliasBuilder.build().
    """

    def __init__(self, graph: AliasGraph):
        self.graph = graph

    def inject(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            for block in fn.blocks:
                block.instructions = self._rewrite_block(
                    block.instructions, fn
                )
        return module

    # ─────────────────────────────────────────────────────────────────────────
    def _rewrite_block(self,
                       instrs: list[IRInstruction],
                       fn: IRFunction) -> list[IRInstruction]:
        out: list[IRInstruction] = []
        for instr in instrs:
            out.extend(self._rewrite_instr(instr, fn))
        return out

    def _rewrite_instr(self,
                       instr: IRInstruction,
                       fn: IRFunction) -> list[IRInstruction]:

        # ── STORE_VAR x ← src ────────────────────────────────────────────────
        if (instr.op == IROp.STORE_VAR
                and len(instr.src) >= 2
                and instr.src[1].kind == "var"):
            var_name = str(instr.src[1].value)
            alias_set = self.graph.get(var_name)
            if alias_set is None or var_name.startswith("__"):
                return [instr]
            return self._expand_store(instr, alias_set, fn)

        # ── LOAD_VAR dst ← x ─────────────────────────────────────────────────
        if (instr.op == IROp.LOAD_VAR
                and instr.dst):
            var_name = None
            for s in instr.src:
                if s.kind == "var" and not str(s.value).startswith("__"):
                    var_name = str(s.value)
                    break
            alias_set = self.graph.get(var_name) if var_name else None
            if alias_set is None:
                return [instr]
            return self._expand_load(instr, alias_set, fn)

        return [instr]

    # ── Store expansion ───────────────────────────────────────────────────────
    def _expand_store(self,
                      instr: IRInstruction,
                      alias_set: AliasSet,
                      fn: IRFunction) -> list[IRInstruction]:
        var   = alias_set.var_name
        result: list[IRInstruction] = []

        # 1. SAG_DEFINE annotation
        result.append(_sag_define_instr(alias_set))

        # 2. Original STORE (real value)
        result.append(instr)

        # 3. SAG_TICK – mutate runtime state
        result.append(_sag_tick_instr(var))

        # 4. Store each fake alias into its own shadow variable
        for i, src in enumerate(alias_set.sources):
            if src.is_real:
                continue
            shadow_var = _sag_alias_var(var, i)
            tmp        = fn.new_temp()
            # Load fake value
            load_fake = IRInstruction(
                op  = IROp.LOAD_CONST,
                dst = _REG(tmp),
                src = [src.operand],
                metadata = {"sag_fake": True, "alias_idx": i},
            )
            store_fake = IRInstruction(
                op  = IROp.STORE_VAR,
                src = [_REG(tmp), _VAR(shadow_var)],
                metadata = {"sag_fake": True, "alias_idx": i},
            )
            result.extend([load_fake, store_fake])

        return result

    # ── Load expansion ────────────────────────────────────────────────────────
    def _expand_load(self,
                     instr: IRInstruction,
                     alias_set: AliasSet,
                     fn: IRFunction) -> list[IRInstruction]:
        var    = alias_set.var_name
        result: list[IRInstruction] = []

        # 1. Compute alias selector index
        idx_tmp = fn.new_temp()
        sel_instr = IRInstruction(
            op  = IROp.NOP,
            dst = _REG(idx_tmp),
            src = [_CONST(alias_set.select_key), _CONST(alias_set.n_aliases())],
            metadata = {
                "sag_op":  SAG_SELECT,
                "var":     var,
                "key":     alias_set.select_key,
                "n":       alias_set.n_aliases(),
            },
        )
        result.append(sel_instr)

        # 2. Load real value (original load kept)
        real_tmp = fn.new_temp()
        real_load = IRInstruction(
            op  = IROp.LOAD_VAR,
            dst = _REG(real_tmp),
            src = instr.src,
            metadata = {"sag_real_load": True},
        )
        result.append(real_load)

        # 3. Load each fake shadow variable
        fake_tmps: list[str] = []
        for i, src in enumerate(alias_set.sources):
            if src.is_real:
                continue
            shadow_var = _sag_alias_var(var, i)
            ftmp       = fn.new_temp()
            load_fake  = IRInstruction(
                op  = IROp.LOAD_VAR,
                dst = _REG(ftmp),
                src = [_VAR(shadow_var)],
                metadata = {"sag_fake_load": True, "alias_idx": i},
            )
            result.append(load_fake)
            fake_tmps.append(ftmp)

        # 4. SAG_COMBINE: pick real value from alias set
        all_tmps = [real_tmp] + fake_tmps
        combine  = _sag_combine_instr(instr.dst, alias_set, all_tmps)
        result.append(combine)

        return result
