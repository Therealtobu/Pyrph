"""
SAG IR nodes – alias-aware extensions to the base IR.

AliasSet:
    Represents a variable that has N possible sources.
    At runtime, exactly one source is "live" per step.
    
    real_idx  : index of the real alias (the one that matters)
    sources   : list of (IROperand, lifetime_fn_name)
    select_fn : how to pick active alias = f(state, history, step)

AliasSelectOp (pseudo-instruction emitted into IR):
    SAG_ALIAS_DEFINE  – define a new alias set for a variable
    SAG_ALIAS_SELECT  – resolve which alias is live this step
    SAG_ALIAS_READ    – read through alias set (may return any live alias)
    SAG_ALIAS_COMBINE – y = combine(all alias(x) + 1) for propagation
    SAG_ALIAS_RETIRE  – alias lifetime ends (for lifetime distortion)

AliasGraph:
    Tracks all alias sets + their cross-variable dependencies.
    Used by SAGPass to detect cycles and manage lifetimes.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Any, Optional

from ir.nodes import IROperand, IRInstruction, IROp


# ── Pseudo-opcodes (stored as metadata on IROp.NOP instructions) ──────────────
SAG_DEFINE  = "SAG_ALIAS_DEFINE"
SAG_SELECT  = "SAG_ALIAS_SELECT"
SAG_READ    = "SAG_ALIAS_READ"
SAG_COMBINE = "SAG_ALIAS_COMBINE"
SAG_RETIRE  = "SAG_ALIAS_RETIRE"

_MASK32 = 0xFFFF_FFFF


# ── Alias source descriptor ───────────────────────────────────────────────────
@dataclass
class AliasSource:
    operand:    IROperand          # the actual value / expression
    is_real:    bool               # True = real value, False = decoy
    alive_from: int                # step number alias becomes valid
    alive_to:   int                # step number alias expires (0 = forever)
    condition:  Optional[str]      # e.g. "state%3==0" as string tag
    
    def is_live(self, step: int, state: int) -> bool:
        if self.alive_to > 0 and step >= self.alive_to:
            return False
        if step < self.alive_from:
            return False
        return True


# ── Alias set for one variable ────────────────────────────────────────────────
@dataclass
class AliasSet:
    var_name:   str
    sources:    list[AliasSource]  = field(default_factory=list)
    real_idx:   int                = 0      # index of real source in sources
    select_key: int                = 0      # part of selection formula key

    def real_source(self) -> AliasSource:
        return self.sources[self.real_idx]

    def fake_sources(self) -> list[AliasSource]:
        return [s for i, s in enumerate(self.sources) if i != self.real_idx]

    def n_aliases(self) -> int:
        return len(self.sources)

    def selection_formula(self) -> str:
        """
        Returns a string formula for runtime alias selection.
        result = (state ^ history_hash ^ step ^ key) % N
        where N = number of sources.
        """
        n   = self.n_aliases()
        key = self.select_key
        return f"((state ^ history ^ step ^ {key}) % {n})"


# ── Cross-variable alias graph ────────────────────────────────────────────────
class AliasGraph:
    """
    Tracks all alias sets and cross-variable dependencies.
    
    Nodes: variable names
    Edges: var A aliases var B → A depends on B's alias resolution
    
    Deliberately creates cycles: x aliases y, y aliases z, z aliases x
    → breaks DAG assumption of standard def-use analysis
    """

    def __init__(self):
        self._sets:  dict[str, AliasSet]    = {}   # var → AliasSet
        self._edges: dict[str, list[str]]   = {}   # var → [vars it aliases]
        self._step_counter: int             = 0

    def register(self, alias_set: AliasSet):
        self._sets[alias_set.var_name] = alias_set
        self._edges.setdefault(alias_set.var_name, [])

    def add_cross_alias(self, from_var: str, to_var: str):
        """from_var has an alias that references to_var → creates dependency edge."""
        self._edges.setdefault(from_var, []).append(to_var)
        self._edges.setdefault(to_var, [])

    def get(self, var_name: str) -> Optional[AliasSet]:
        return self._sets.get(var_name)

    def all_vars(self) -> list[str]:
        return list(self._sets.keys())

    def has_cycles(self) -> bool:
        """Check if cross-alias graph contains cycles (expected: yes)."""
        visited = set()
        rec_stack = set()

        def _dfs(v):
            visited.add(v)
            rec_stack.add(v)
            for nbr in self._edges.get(v, []):
                if nbr not in visited:
                    if _dfs(nbr):
                        return True
                elif nbr in rec_stack:
                    return True
            rec_stack.discard(v)
            return False

        return any(_dfs(v) for v in self._sets if v not in visited)

    def emit_runtime_header(self) -> str:
        """Python source injected into output: SAG runtime state."""
        return (
            "# SAG runtime state\n"
            "__sag_state   = 0xDEADBEEF\n"
            "__sag_history = []\n"
            "__sag_step    = 0\n\n"
            "def __sag_tick(value):\n"
            "    global __sag_state, __sag_step\n"
            "    __sag_history.append(hash(str(value)) & 0xFFFFFFFF)\n"
            "    if len(__sag_history) > 16: __sag_history.pop(0)\n"
            "    __sag_state = (__sag_state ^ hash(tuple(__sag_history))) & 0xFFFFFFFF\n"
            "    __sag_step += 1\n\n"
            "def __sag_sel(key, n):\n"
            "    h = hash(tuple(__sag_history)) & 0xFFFFFFFF if __sag_history else 0\n"
            "    return (__sag_state ^ h ^ __sag_step ^ key) % n\n\n"
            "def __sag_combine(vals, key):\n"
            "    \"\"\"XOR-fold all alias values → extract real via key.\"\"\"\n"
            "    folded = 0\n"
            "    for i, v in enumerate(vals):\n"
            "        if isinstance(v, int):\n"
            "            folded ^= v ^ (key >> (i & 15))\n"
            "    return folded\n"
        )
