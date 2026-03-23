"""
AliasBuilder – analyzes IRModule and decides which variables
get alias sets + how many fake aliases to inject.

Strategy:
  1. Collect all STORE_VAR targets in each function
  2. For each target (non-dunder, non-temp):
     a. Create 1 real alias (original value)
     b. Inject 2–3 fake aliases (plausible-looking decoys)
     c. Add 1–2 cross-variable aliases (from OTHER variables → creates cycles)
  3. Build AliasGraph

Fake alias types:
  TYPE_CONST    : const ^ session_key (looks like encoded constant)
  TYPE_PREV_XOR : prev_real ^ rolling_state (looks like MBA)
  TYPE_CROSS_VAR: reference to another variable's alias set

Lifetime distortion:
  Real alias: always valid
  Fake aliases: random alive_from/alive_to windows
  → at any step, multiple aliases appear "active" but only real matters
"""
from __future__ import annotations
import itertools
import random

from ..ir.nodes import (
    IROp, IROperand, IRInstruction,
    IRFunction, IRModule,
)
from .alias_node import (
    AliasSource, AliasSet, AliasGraph,
    SAG_DEFINE, SAG_SELECT, SAG_READ, SAG_COMBINE, SAG_RETIRE,
)

_MASK32    = 0xFFFF_FFFF
_N_FAKES   = 2          # fake aliases per variable
_CROSS_PROB= 0.40       # probability of adding cross-variable alias
_ctr       = itertools.count(1)

_REG  = lambda n: IROperand("reg",   n)
_VAR  = lambda n: IROperand("var",   n)
_CONST= lambda v: IROperand("const", v)


def _fake_const(real_val: IROperand) -> IROperand:
    """Generate a fake constant operand that looks plausible."""
    k = random.randint(0x10, 0xFFFF)
    if real_val.kind == "const" and isinstance(real_val.value, int):
        return _CONST((real_val.value ^ k) + random.randint(-5, 5))
    return _CONST(random.randint(0, 0xFFFF))


class AliasBuilder:

    def __init__(self,
                 n_fakes:    int   = _N_FAKES,
                 cross_prob: float = _CROSS_PROB):
        self.n_fakes    = n_fakes
        self.cross_prob = cross_prob

    def build(self, module: IRModule) -> AliasGraph:
        graph = AliasGraph()

        for fn in module.functions:
            self._process_function(fn, graph)

        return graph

    # ─────────────────────────────────────────────────────────────────────────
    def _process_function(self, fn: IRFunction, graph: AliasGraph):
        # Collect all stored variable names + their real source operands
        stored: dict[str, IROperand] = {}

        for block in fn.blocks:
            for instr in block.instructions:
                if (instr.op == IROp.STORE_VAR
                        and len(instr.src) >= 2
                        and instr.src[1].kind == "var"):
                    var_name = str(instr.src[1].value)
                    if not var_name.startswith("__"):
                        stored[var_name] = instr.src[0]

        var_names = list(stored.keys())
        if not var_names:
            return

        for var_name, real_src in stored.items():
            alias_set = self._build_alias_set(
                var_name, real_src, var_names, graph
            )
            graph.register(alias_set)

        # Add cross-variable alias edges (creates cycles)
        for var_name in var_names:
            if random.random() < self.cross_prob and len(var_names) > 1:
                other = random.choice([v for v in var_names if v != var_name])
                graph.add_cross_alias(var_name, other)

    # ─────────────────────────────────────────────────────────────────────────
    def _build_alias_set(self,
                         var_name:  str,
                         real_src:  IROperand,
                         all_vars:  list[str],
                         graph:     AliasGraph) -> AliasSet:
        select_key = random.randint(1, _MASK32)
        total_steps = 1000   # assume program < 1000 IR steps

        # Real alias – always live
        real = AliasSource(
            operand   = real_src,
            is_real   = True,
            alive_from= 0,
            alive_to  = 0,      # 0 = forever
            condition = None,
        )

        sources = [real]
        real_idx = 0

        # Fake aliases with random lifetimes
        for i in range(self.n_fakes):
            fake_op = self._make_fake_operand(real_src, all_vars, var_name)
            alive_from = random.randint(0, total_steps // 3)
            alive_to   = random.randint(alive_from + 10, total_steps)
            # Randomise condition tag
            cond = random.choice([
                "state%3==0", "step%2==0", "history_len>4", None,
            ])
            fake = AliasSource(
                operand   = fake_op,
                is_real   = False,
                alive_from= alive_from,
                alive_to  = alive_to,
                condition = cond,
            )
            sources.append(fake)

        # Shuffle so real_idx is not always 0
        real_alias = sources[0]
        random.shuffle(sources)
        real_idx = sources.index(real_alias)

        return AliasSet(
            var_name   = var_name,
            sources    = sources,
            real_idx   = real_idx,
            select_key = select_key,
        )

    def _make_fake_operand(self,
                           real_src: IROperand,
                           all_vars: list[str],
                           exclude:  str) -> IROperand:
        """Create a plausible-looking fake operand for an alias source."""
        choice = random.randint(0, 2)
        if choice == 0:
            # Fake constant
            return _fake_const(real_src)
        elif choice == 1 and len(all_vars) > 1:
            # Reference to another variable (cross-variable)
            other = random.choice([v for v in all_vars if v != exclude])
            return _VAR(other)
        else:
            # MBA-like expression encoded as a constant
            k = random.randint(1, 0xFFFF)
            if real_src.kind == "const" and isinstance(real_src.value, int):
                return _CONST(((real_src.value | k) - (real_src.value & k)))
            return _CONST(random.randint(0, 0xFFFF))
