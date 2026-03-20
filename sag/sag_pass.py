"""
SAGPass – Phase 4.5 orchestrator.

Pipeline position:
    IR Build
      ↓
    IR Obf  (import-obf, semantic-fp, substitution, shuffle, rewrite, encrypt)
      ↓
    ★ SAGPass  ← HERE
      ↓
    Metamorphic Engine
      ↓
    VM Compile

Steps:
  1. AliasBuilder.build()  → AliasGraph
  2. SAGIRInjector.inject() → rewrite IR with alias instructions
  3. Store graph in module metadata for codegen to emit runtime

Config:
  MIN_VARS      : min distinct variables in function to trigger SAG
  N_FAKES       : number of fake aliases per variable
  CROSS_PROB    : probability of cross-variable alias edges
"""
from __future__ import annotations

from ir.nodes import IRModule
from .alias_builder  import AliasBuilder
from .ir_injector    import SAGIRInjector
from .runtime_emitter import SAGRuntimeEmitter

_MIN_VARS   = 1
_N_FAKES    = 2
_CROSS_PROB = 0.40


class SAGPass:

    def __init__(self,
                 min_vars:   int   = _MIN_VARS,
                 n_fakes:    int   = _N_FAKES,
                 cross_prob: float = _CROSS_PROB):
        self.min_vars   = min_vars
        self.n_fakes    = n_fakes
        self.cross_prob = cross_prob
        self._emitter   = SAGRuntimeEmitter()

    def run(self, module: IRModule) -> IRModule:
        # 1. Build alias graph
        builder = AliasBuilder(
            n_fakes    = self.n_fakes,
            cross_prob = self.cross_prob,
        )
        graph = builder.build(module)

        # 2. Inject alias IR
        if graph.all_vars():
            injector = SAGIRInjector(graph)
            module   = injector.inject(module)

        # 3. Attach graph + runtime emitter to module for codegen
        module.__dict__['_sag_graph']   = graph
        module.__dict__['_sag_emitter'] = self._emitter

        return module

    @staticmethod
    def get_runtime(module: IRModule) -> str:
        """Called by codegen to get SAG runtime source."""
        emitter = module.__dict__.get('_sag_emitter')
        if emitter:
            return emitter.emit_runtime()
        return ""

    @staticmethod
    def get_graph_stats(module: IRModule) -> dict:
        """Diagnostic: return stats about the alias graph."""
        graph = module.__dict__.get('_sag_graph')
        if not graph:
            return {"vars": 0, "edges": 0, "has_cycles": False}
        return {
            "vars":       len(graph.all_vars()),
            "edges":      sum(len(v) for v in graph._edges.values()),
            "has_cycles": graph.has_cycles(),
        }
