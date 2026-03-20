"""
sag – Semantic Alias Graph (Phase 4.5)

Runs AFTER IR Obf, BEFORE VM.

Core idea: every variable loses its single fixed identity.
Instead of   x → value_5
We get       x → alias_set(A_real, B_fake, C_fake)
             where only one alias is "live" at any given execution step,
             selected by (state ^ history ^ step_counter) % len(aliases)

This breaks:
  - SSA (1 variable = 1 definition source) → multi-origin
  - Def-use chain analysis → every use has N possible defs
  - Constant propagation → no static value for any alias
  - Taint tracking → taint propagates through ALL aliases, not just real one
"""
