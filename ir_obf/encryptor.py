"""
BlockEncryptor – assigns a unique encryption key to each IRBlock and
"encrypts" the encoded opcode values of every instruction in that block.

Encryption model
----------------
Each block gets:
  key_b  = random 32-bit integer

For each instruction in block b:
  enc_op = (raw_op_id ^ key_b ^ rolling_state) + position
  rolling_state = (rolling_state * 0x5851F42D + position) & 0xFFFFFFFF

The rolling_state is seeded from the block key so it changes with every
block.  The VM's polymorphic resolver (vm/resolver.py) uses the same
formula to decode at runtime.

Additionally, src operand constants are XOR-masked with a derived mask:
  operand_mask = (key_b >> (pos & 15)) & 0xFF
so static operand extraction requires knowing both key_b and position.

Results stored:
  block.encrypt_key         = key_b
  instr.enc_op              = encrypted opcode int
  instr.metadata["enc_pos"] = position within block (for VM decoder)
  instr.metadata["key_b"]   = key_b  (so codegen can embed it)
"""
from __future__ import annotations
import random
from ir.nodes import IROp, IRInstruction, IRBlock, IRModule

_MASK32 = 0xFFFFFFFF
_MUL    = 0x5851F42D   # LCG multiplier (from SplitMix64)


class BlockEncryptor:

    def run(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            for block in fn.blocks:
                self._encrypt_block(block)
        return module

    # ─────────────────────────────────────────────────────────────────────────
    def _encrypt_block(self, block: IRBlock):
        key_b = random.randint(1, _MASK32)
        block.encrypt_key = key_b

        state = key_b
        for pos, instr in enumerate(block.instructions):
            raw_op = instr.op.value            # integer id from enum
            enc_op = ((raw_op ^ key_b ^ state) + pos) & _MASK32
            instr.enc_op              = enc_op
            instr.metadata["enc_pos"] = pos
            instr.metadata["key_b"]   = key_b

            # Encrypt constant src operands
            op_mask = (key_b >> (pos & 15)) & 0xFF
            for operand in instr.src:
                if operand.kind == "const" and isinstance(operand.value, int):
                    operand.value = operand.value ^ op_mask
                    operand.metadata_mask = op_mask   # type: ignore[attr-defined]

            # Advance rolling state (LCG step)
            state = ((state * _MUL) + pos) & _MASK32

    # ── Static decode (used by VM codegen to verify) ──────────────────────────
    @staticmethod
    def decode_op(enc_op: int, key_b: int, pos: int, state: int) -> int:
        """Inverse of _encrypt_block for a single instruction."""
        return ((enc_op - pos) & _MASK32) ^ key_b ^ state

    @staticmethod
    def advance_state(state: int, pos: int) -> int:
        return ((state * _MUL) + pos) & _MASK32
