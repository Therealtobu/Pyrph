"""
SemanticFingerprintPass – instruments STORE_VAR + LOAD_VAR với shadow tracking.

Shadow formula (chain-dependent – không thể recompute local):
    shadow[var] = hash((value, prev_shadow[var], vm_state, instr_id)) & 0xFFFF_FFFF

Nếu bất kỳ STORE nào bị patch:
  → shadow desync tại điểm đó
  → mọi LOAD phía sau bị corrupt âm thầm
  → không raise, không crash – output sai dần
"""
from __future__ import annotations
import itertools
from ..ir.nodes import IROp, IROperand, IRInstruction, IRFunction, IRModule

_ctr = itertools.count(1)    # global – mỗi instruction dùng một lần

_REG  = lambda n: IROperand("reg",   n)
_VAR  = lambda n: IROperand("var",   n)
_CONST= lambda v: IROperand("const", v)

_SHADOW_PROP  = "SHADOW_PROP"
_SHADOW_WRITE = "SHADOW_WRITE"
_SHADOW_CHECK = "SHADOW_CHECK"


def _shadow_var(name: str) -> str:
    return f"__sh_{name}"


class SemanticFingerprintPass:
    """Chạy SAU IRBuilder, TRƯỚC InstructionSubstitutor."""

    def run(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            self._instrument_fn(fn)
        return module

    def _instrument_fn(self, fn: IRFunction):
        for block in fn.blocks:
            block.instructions = self._instrument_block(block.instructions)

    def _instrument_block(self, instrs: list) -> list:
        out = []
        for instr in instrs:
            out.extend(self._wrap(instr))
        return out

    def _wrap(self, instr: IRInstruction) -> list[IRInstruction]:

        # ── STORE_VAR x ← src ────────────────────────────────────────────
        if instr.op == IROp.STORE_VAR and len(instr.src) >= 2:
            var_name = str(instr.src[1].value)
            if var_name.startswith("__"):
                return [instr]   # skip internal vars

            sh_name  = _shadow_var(var_name)
            src_op   = instr.src[0]

            iid_prop  = next(_ctr)   # unique id for PROP
            iid_write = next(_ctr)   # unique id for WRITE

            prop = IRInstruction(
                op  = IROp.NOP,
                dst = _VAR(sh_name),
                src = [src_op, _VAR(sh_name), _CONST(iid_prop)],
                metadata={"shadow_op": _SHADOW_PROP,
                          "var": var_name, "iid": iid_prop},
            )
            write = IRInstruction(
                op  = IROp.NOP,
                dst = _VAR(sh_name),
                src = [src_op, _CONST(iid_write)],
                metadata={"shadow_op": _SHADOW_WRITE,
                          "var": var_name, "iid": iid_write},
            )
            return [prop, instr, write]

        # ── LOAD_VAR dst ← x ─────────────────────────────────────────────
        if instr.op == IROp.LOAD_VAR and instr.dst:
            var_name = None
            for s in instr.src:
                if s.kind == "var" and not str(s.value).startswith("__"):
                    var_name = str(s.value)
                    break
            if var_name:
                sh_name = _shadow_var(var_name)
                iid_chk = next(_ctr)
                check   = IRInstruction(
                    op  = IROp.NOP,
                    dst = instr.dst,
                    src = [_VAR(sh_name), instr.dst, _CONST(iid_chk)],
                    metadata={"shadow_op": _SHADOW_CHECK,
                              "var": var_name, "iid": iid_chk},
                )
                return [instr, check]

        return [instr]
