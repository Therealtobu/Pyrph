"""
BytecodeIntegrityChain – thêm rolling hash chain vào instruction stream.

Cơ chế:
    chain[0] = seed
    chain[i] = hash(chain[i-1], enc_op[i], repr(operands[i])) & MASK32

Mỗi instruction mang thêm field "ch" = expected chain value.
VM verify chain[i] match trước khi execute instruction i.
Nếu fail → không raise → silent corruption qua _chain_poison().

Tamper detection:
    - Xóa 1 instruction → chain[i+1] fail vì chain[i] đã đổi
    - Thêm fake instruction → chain shift lệch
    - Sửa enc_op → chain fail ngay tại điểm đó
    - Đảo thứ tự → chain fail

Silent thay vì crash → attacker không biết chỗ nào bị detect.

Compile-time: IntegrityChainBuilder.build(bc) → annotate tất cả VM3Instr
Runtime: emit_runtime() → _ICV class được inline vào output
"""
from __future__ import annotations

_MASK32 = 0xFFFF_FFFF


class IntegrityChainBuilder:

    def __init__(self, seed: int | None = None):
        import random
        self._seed = seed if seed is not None else random.randint(1, _MASK32)

    def build(self, instructions: list) -> tuple[list, int]:
        """
        Annotate each VM3Instr with .meta["ch"] = expected chain value.
        Returns (annotated_instrs, seed).
        """
        chain = self._seed
        for instr in instructions:
            chain = self._step(chain, instr.enc_op,
                               repr(instr.operands).encode())
            instr.meta = getattr(instr, 'meta', {})
            instr.meta["ch"] = chain
        return instructions, self._seed

    @staticmethod
    def _step(chain: int, enc_op: int, operand_bytes: bytes) -> int:
        h = hash((chain, enc_op, operand_bytes)) & _MASK32
        # Extra mixing: FNV-1a style over operand bytes
        for b in operand_bytes[:32]:   # cap at 32 bytes
            h = ((h ^ b) * 0x01000193) & _MASK32
        return h ^ (chain >> 7)

    @staticmethod
    def emit_runtime() -> str:
        return r'''
_IC_MASK = 0xFFFFFFFF
_IC_FNV  = 0x01000193

class _ICV:
    """Bytecode integrity chain verifier – runtime."""
    def __init__(self, seed: int):
        self._chain  = seed
        self._poison = False    # once poisoned, stays poisoned

    def verify(self, enc_op: int, operands, expected_ch: int) -> bool:
        op_bytes = repr(operands).encode()
        h        = hash((self._chain, enc_op, op_bytes)) & _IC_MASK
        for b in op_bytes[:32]:
            h = ((h ^ b) * _IC_FNV) & _IC_MASK
        self._chain = h ^ (self._chain >> 7)

        if self._chain != expected_ch:
            self._poison = True
            return False
        return True

    def is_poisoned(self) -> bool:
        return self._poison
'''

    @staticmethod
    def emit_vm3_verify_call() -> str:
        """
        Đoạn code chèn vào _VM3.run() trước mỗi dispatch.
        Nếu chain fail → corrupt resolver state thay vì crash.
        """
        return (
            "            if hasattr(self, '_icv') and ins.get('ch') is not None:\n"
            "                if not self._icv.verify(enc, ops, ins['ch']):\n"
            "                    self.r1.key = (self.r1.key ^ 0xBADC0FFE) & 0xFFFFFFFF\n"
            "                    self.r2.key = (self.r2.key ^ 0xDEADC0DE) & 0xFFFFFFFF\n"
        )
