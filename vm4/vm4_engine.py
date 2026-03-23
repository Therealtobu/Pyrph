"""
VM4Engine – orchestrates all 4 layers.

Runtime loop:
  1. FragmentGraphBuilder → FragmentGraph (compile-time)
  2. StateMesh init with DNA seed + SAG + MCP hooks
  3. ExecutionFabric.run() → (sm_state, dna_partial, hist)
  4. DNALock.reconstruct() → final output

Emits all 4 layers as Python source into output file.
Called by VMCodeGen as an alternative to VM3 (or as a wrapper on top).

Integration with existing pipeline:
  - Codegen calls vm4_engine.emit_all() after all other security modules
  - VM4 wraps the existing VM3 execution, adding the DNA lock layer
  - This means: attacker who breaks VM3 still faces VM4 DNA verification
"""
from __future__ import annotations
import json
import zlib
import base64

from ..ir.nodes import IRModule
from .fragment_graph  import FragmentGraphBuilder, FragmentGraph
from .execution_fabric import ExecutionFabricEmitter
from .state_mesh       import StateMeshEmitter
from .dna_lock         import DNALockEmitter


class VM4Engine:

    def __init__(self, frags_per_op: int = 4, decoy_ratio: float = 0.35):
        self._fg_builder = FragmentGraphBuilder(
            frags_per_op = frags_per_op,
            decoy_ratio  = decoy_ratio,
        )
        self._ef = ExecutionFabricEmitter()
        self._sm = StateMeshEmitter()
        self._dna = DNALockEmitter()

    # ── Build fragment graph from IR ──────────────────────────────────────────
    def build_fragment_graph(self, ir_module: IRModule) -> FragmentGraph:
        """Convert IR instructions to Fragment Graph."""
        all_instrs = []
        for fn in ir_module.functions:
            for instr in fn.all_instructions():
                all_instrs.append({
                    "op":  instr.op.name,
                    "dst": str(instr.dst.value) if instr.dst else "",
                    "src": [str(s.value) for s in instr.src],
                })
        return self._fg_builder.build(all_instrs)

    # ── Emit all VM4 runtime source ───────────────────────────────────────────
    def emit_all_runtime(self, fg: FragmentGraph) -> str:
        parts = [
            "# ════════════════════════════════════════════════════════════════",
            "# VM4: Fragment Graph Execution Engine",
            "# L1:FG + L2:EF + L3:SM + L4:DNA",
            "# No opcode. No instruction. No truth state.",
            "# ════════════════════════════════════════════════════════════════",
            self._ef.emit_runtime(),
            self._sm.emit_runtime(),
            self._dna.emit_runtime(),
            self._ef.emit_init_code(),
            self._emit_fg_data(fg),
            self._emit_vm4_runner(fg),
        ]
        return "\n\n".join(parts)

    def _emit_fg_data(self, fg: FragmentGraph) -> str:
        """Serialize and compress Fragment Graph data."""
        data    = self._fg_builder.serialise(fg)
        raw     = json.dumps(data, separators=(",", ":")).encode()
        comp    = zlib.compress(raw, level=9)
        b64     = base64.b85encode(comp).decode()
        return (
            f"__FG_RAW  = {b64!r}\n"
            "__FG_DATA  = __import__('json').loads(\n"
            "    __import__('zlib').decompress(\n"
            "        __import__('base64').b85decode(__FG_RAW)\n"
            "    )\n"
            ")\n"
            "__FG_POOL  = __FG_DATA['frags']\n"
            "__FG_REAL  = __FG_DATA['real']\n"
        )

    def _emit_vm4_runner(self, fg: FragmentGraph) -> str:
        return r'''
# ── VM4 main runner ───────────────────────────────────────────────────────────
import random as _v4_rand

def _vm4_run(init_env: dict, sag_state_fn=None, mcp_fn=None) -> dict:
    """
    Execute Fragment Graph and return final state mesh.
    init_env: initial variable bindings from VM3 output or program start.
    """
    # Init State Mesh
    dna_seed = (_EF_DNA_SEED ^ hash(str(init_env))) & _EF_MASK
    sm       = _StateMesh(
        dna_seed      = dna_seed,
        sag_state_fn  = sag_state_fn or (lambda: 0),
        mcp_fn        = mcp_fn       or (lambda: 0),
    )

    # Load initial env into state mesh
    for k, v in init_env.items():
        sm.write(k, v)

    # Run execution fabric
    sm_dict, dna_partial, hist = _ef_run(
        pool           = __FG_POOL,
        real_ids       = __FG_REAL,
        sm_state       = sm._shards,   # fabric works directly on shards
        sag_state_fn   = sag_state_fn or (lambda: 0),
        dna_partial_init = dna_seed,
    )

    # Rekey state mesh with final DNA
    sm.rekey(dna_partial)

    # Build visit counts from hist
    visit_counts = {}
    for fid in hist:
        if isinstance(fid, int):
            visit_counts[fid] = visit_counts.get(fid, 0) + 1

    # DNA lock: reconstruct output
    final_val = _dna_reconstruct(
        sm_state     = sm._shards,
        dna_partial  = dna_partial,
        hist         = hist,
        visit_counts = visit_counts,
    )

    return {
        "result":     final_val,
        "sm":         sm,
        "dna":        dna_partial,
        "hist_len":   len(hist),
    }


def _vm4_apply(vm3_result, vm3_state: int,
               sag_state_fn=None, mcp_fn=None):
    """
    Apply VM4 as a post-processing layer on VM3 output.
    vm3_result: raw output from VM3
    vm3_state: r1.state ^ r2.state from VM3

    Returns vm3_result in normal execution (net=0 modification).
    Returns corrupted value if execution path was tampered.
    """
    if not isinstance(vm3_result, int):
        # Non-int: just update DNA state and return unchanged
        try:
            _v4_out = _vm4_run(
                {"__vm3_hash": hash(str(vm3_result)) & _EF_MASK},
                sag_state_fn = sag_state_fn,
                mcp_fn       = mcp_fn,
            )
        except Exception:
            pass
        return vm3_result

    # Int result: run VM4 and use DNA lock to verify
    try:
        init = {"__vm3_result": vm3_result & _EF_MASK,
                "__vm3_state":  vm3_state  & _EF_MASK}
        v4_out   = _vm4_run(init, sag_state_fn, mcp_fn)
        dna      = v4_out["dna"]

        # DNA lock verification (soft – no crash on fail)
        hint = (vm3_result ^ vm3_state) & 0xFFFF
        if _dna_lock_check(hint, dna):
            # Clean execution → return vm3_result unchanged
            return vm3_result
        else:
            # DNA mismatch → subtle corruption
            noise = (dna ^ hint) & 0xFF
            return (vm3_result ^ noise) & 0xFFFFFFFF
    except Exception:
        return vm3_result   # any error → return unchanged
'''
