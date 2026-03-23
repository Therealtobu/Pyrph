"""
MetamorphicEngine – Phase 3.5 orchestrator.

Quy trình:
  1. Với mỗi IRFunction trong module (trừ __module__ và các dunder):
     a. Generate N variants (VariantGenerator)
     b. Build dispatch function (MetamorphicDispatcher)
     c. Inject: variants + dispatcher vào module.functions
     d. Remove original function (dispatcher thay thế)

  2. Inject module preamble (__mm_key, __mm_ctr)

Config:
  MIN_BLOCK_COUNT : chỉ metamorphize functions có >= N blocks
  MIN_INSTR_COUNT : chỉ metamorphize functions có >= N instructions
  N_VARIANTS      : số variants (default 3)

Các function nhỏ (< threshold) không bị metamorphize để tránh
output quá phình. Function splitting ở Transform phase đã xử lý rồi.
"""
from __future__ import annotations

from ir.nodes import IRModule, IRFunction, IRInstruction, IROp, IROperand
from .variant_generator import VariantGenerator
from .dispatcher        import MetamorphicDispatcher

_MIN_BLOCKS = 2
_MIN_INSTRS = 4
_N_VARIANTS = 3

_SKIP_NAMES = {"__module__"}


class MetamorphicEngine:

    def __init__(self,
                 n_variants:  int = _N_VARIANTS,
                 min_blocks:  int = _MIN_BLOCKS,
                 min_instrs:  int = _MIN_INSTRS):
        self.n_variants = n_variants
        self.min_blocks = min_blocks
        self.min_instrs = min_instrs
        self._gen  = VariantGenerator(n_variants)
        self._disp = MetamorphicDispatcher()

    def run(self, module: IRModule) -> IRModule:
        # Snapshot original list – don't iterate while mutating
        originals = [fn for fn in module.functions
                     if self._should_metamorphize(fn)]

        injected: list[IRFunction] = []

        for fn in originals:
            variants   = self._gen.generate(fn)
            dispatcher = self._disp.build_dispatcher(fn, variants, module)

            injected.extend(variants)
            injected.append(dispatcher)

        # Replace originals with dispatchers + add variants
        if injected:
            original_names = {fn.name for fn in originals}
            kept = [fn for fn in module.functions
                    if fn.name not in original_names]
            module.functions = kept + injected

        # Inject __mm_key/__mm_ctr into module globals init
        self._inject_preamble(module)

        return module

    def _should_metamorphize(self, fn: IRFunction) -> bool:
        if fn.name in _SKIP_NAMES:
            return False
        if fn.name.startswith("__") and fn.name.endswith("__"):
            return False
        # Skip already-generated variants/dispatchers
        if "__var" in fn.name or "dispatch" in fn.name:
            return False
        n_blocks = len(fn.blocks)
        n_instrs = sum(len(b.instructions) for b in fn.blocks)
        return n_blocks >= self.min_blocks or n_instrs >= self.min_instrs

    @staticmethod
    def _inject_preamble(module: IRModule):
        """Add __mm_key and __mm_ctr LOAD instructions to globals."""
        # These are injected as IR constants that codegen will emit
        # as Python source at the top of the output file.
        module.globals_init.insert(0, IRInstruction(
            op=IROp.NOP,
            metadata={"metamorphic_preamble": True},
        ))
