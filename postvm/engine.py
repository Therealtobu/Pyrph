"""
PostVMEngine – orchestrates all post-VM protection layers.

Layer execution order per function return:
  1. PDL.apply()   → sample phantom entropy (updates _PDL_SEED)
  2. TBL.apply()   → temporal bind + unbind (updates hist)
  3. OEL.combined()→ entangle + disentangle (updates _OEL_MASK)
  4. DLI.apply()   → deferred logic fragment (updates _DLI_HIST)
  5. PEIL.verify() → integrity check (final gate)

All layers are emitted as Python source injected into codegen output.
The _VM3.run() method is patched to call __postvm_apply(result, vm_state)
before returning.

If attacker skips any layer:
  - PEIL sees wrong vm_state  → corrupts result
  - OEL mask is wrong         → future functions return wrong values
  - TBL hist is wrong         → downstream calls drift
  - PDL seed is wrong         → PEIL checkpoint deviates
"""
from __future__ import annotations

from .peil import PEILEmitter
from .dli  import DLIEmitter
from .oel  import OELEmitter
from .tbl  import TBLEmitter
from .pdl  import PDLEmitter


class PostVMEngine:

    def __init__(self):
        self._peil = PEILEmitter()
        self._dli  = DLIEmitter()
        self._oel  = OELEmitter()
        self._tbl  = TBLEmitter()
        self._pdl  = PDLEmitter()

    def emit_all_runtime(self) -> str:
        """
        Emit all post-VM layer runtime code.
        Order matters: PDL → TBL → OEL → DLI → PEIL.
        """
        parts = [
            "# ════════════════════════════════════════════════════════════════",
            "# POST-VM PROTECTION LAYERS (Stage 7)",
            "# PDL → TBL → OEL → DLI → PEIL",
            "# ════════════════════════════════════════════════════════════════",
            self._pdl.emit_runtime(),
            self._tbl.emit_runtime(),
            self._oel.emit_runtime(),
            self._dli.emit_runtime(),
            self._peil.emit_runtime(),
            self._emit_combined_apply(),
        ]
        return "\n".join(parts)

    @staticmethod
    def _emit_combined_apply() -> str:
        """
        __postvm_apply() – the single entry point called by _VM3.run()
        before every return.

        Chains all 5 layers in order.
        Net effect on result in NORMAL execution = identity (result unchanged).
        Net effect in TAMPERED execution = silent corruption at one or more layers.
        """
        return r'''
# ── Combined post-VM pipeline ─────────────────────────────────────────────────
_POSTVM_INIT_CKPT = 0   # set by bootstrap


def __postvm_init(vm3_instance):
    """Called once at startup to set initial PEIL checkpoint."""
    global _POSTVM_INIT_CKPT
    _POSTVM_INIT_CKPT = __peil_checkpoint(
        vm3_instance.r1.state ^ vm3_instance.r2.state,
        globals().get("__sag_state", 0),
    )


def __postvm_apply(result, vm_state: int, fn_id: int = 0):
    """
    Apply all post-VM protection layers to a result.

    Layer 1: PDL  – sample phantom entropy (non-deterministic)
    Layer 2: TBL  – temporal bind (history + time)
    Layer 3: OEL  – output entanglement (global mask)
    Layer 4: DLI  – deferred logic injection
    Layer 5: PEIL – integrity verify (final gate)
    """
    # Layer 1: PDL – phantom entropy sampling (updates _PDL_SEED)
    result = __pdl_apply(result, vm_state)

    # Layer 2: TBL – temporal binding (net=0, updates history)
    result = __tbl_apply(result, vm_state)

    # Layer 3: OEL – output entanglement (net=0, updates mask)
    result = __oel_combined(result, vm_state)

    # Layer 4: DLI – deferred logic injection
    if fn_id and fn_id in _DLI_FRAGS:
        enc_frag, frag_type = _DLI_FRAGS[fn_id]
        result = __dli_apply(result, fn_id, enc_frag, vm_state, frag_type)

    # Layer 5: PEIL – final integrity verification (may corrupt if tampered)
    sag_state = globals().get("__sag_state", 0) ^ __pdl_seed()
    result    = __peil_verify(result, _POSTVM_INIT_CKPT, vm_state, sag_state)

    return result
'''

    def emit_dli_fragment_table(self, fn_names: list[str]) -> str:
        """Register all functions and emit encrypted fragment table."""
        for name in fn_names:
            self._dli.register_function(name)
        return self._dli.emit_fragment_table()

    def emit_vm3_run_patch(self) -> str:
        """
        Replacement for _VM3.run() return statement.
        Wraps self.ret through __postvm_apply before returning.
        """
        return (
            "        _pvm_state = (self.r1.state ^ self.r2.state) & 0xFFFFFFFF\n"
            "        _pvm_fn_id = hash(str(id(self))) & 0xFFFFFFFF\n"
            "        __peil_enter(_pvm_fn_id)\n"
            "        _pvm_ckpt  = __peil_checkpoint(_pvm_state, globals().get('__sag_state',0))\n"
        )

    def emit_bootstrap_init(self) -> str:
        """Inject into bootstrap after __vm is created."""
        return (
            "__postvm_init(__vm)\n"
            "__peil_enter(0)\n"
        )
