import sys; sys.path.insert(0, '.')
import unittest
from ..vm.integrity_chain import IntegrityChainBuilder

exec(IntegrityChainBuilder.emit_runtime())   # defines _ICV  # noqa


def _make_fake_instr(enc_op: int, operands=None):
    class _I:
        def __init__(self, e, o):
            self.enc_op   = e
            self.operands = o or []
            self.meta     = {}
    return _I(enc_op, operands)


class TestIntegrityChain(unittest.TestCase):

    def test_valid_chain_all_pass(self):
        """verify() returns True for every instruction in a non-tampered stream."""
        instrs = [_make_fake_instr(i * 7 + 3, [i, i+1]) for i in range(20)]
        builder = IntegrityChainBuilder(seed=0xABCDEF)
        annotated, seed = builder.build(instrs)

        verifier = _ICV(seed)  # noqa
        for ins in annotated:
            ok = verifier.verify(ins.enc_op, ins.operands, ins.meta["ch"])
            self.assertTrue(ok, f"valid instr failed verify: enc={ins.enc_op}")

    def test_tampered_enc_op_detected(self):
        """Flipping enc_op of any instruction must trigger chain failure."""
        instrs   = [_make_fake_instr(i * 5 + 1) for i in range(10)]
        builder  = IntegrityChainBuilder(seed=0x1234)
        annotated, seed = builder.build(instrs)

        # Tamper instruction 5
        annotated[5].enc_op ^= 0xFF

        verifier = _ICV(seed)  # noqa
        results  = []
        for ins in annotated:
            ok = verifier.verify(ins.enc_op, ins.operands, ins.meta["ch"])
            results.append(ok)

        self.assertFalse(any(results[5:]),
            "tampered instruction and all subsequent should fail")

    def test_extra_instruction_detected(self):
        """Inserting a fake instruction breaks chain from that point."""
        instrs  = [_make_fake_instr(i) for i in range(8)]
        builder = IntegrityChainBuilder(seed=0x9999)
        annotated, seed = builder.build(instrs)

        # Insert fake instr at position 3
        fake = _make_fake_instr(0xDEAD)
        fake.meta = {"ch": 0}   # wrong ch
        annotated.insert(3, fake)

        verifier = _ICV(seed)  # noqa
        fail_count = 0
        for ins in annotated:
            if not verifier.verify(ins.enc_op, ins.operands, ins.meta.get("ch", 0)):
                fail_count += 1

        self.assertGreater(fail_count, 0, "inserted instruction not detected")

    def test_poison_flag_set_on_fail(self):
        """_ICV.is_poisoned() must return True after any chain failure."""
        instrs  = [_make_fake_instr(i) for i in range(5)]
        builder = IntegrityChainBuilder(seed=0x5555)
        annotated, seed = builder.build(instrs)

        annotated[2].enc_op ^= 1   # tamper

        verifier = _ICV(seed)  # noqa
        self.assertFalse(verifier.is_poisoned())
        for ins in annotated:
            verifier.verify(ins.enc_op, ins.operands, ins.meta["ch"])
        self.assertTrue(verifier.is_poisoned())

    def test_different_seeds_different_chains(self):
        """Same instructions with different seeds → different chain values."""
        instrs1 = [_make_fake_instr(i) for i in range(5)]
        instrs2 = [_make_fake_instr(i) for i in range(5)]

        _, _ = IntegrityChainBuilder(seed=0x1111).build(instrs1)
        _, _ = IntegrityChainBuilder(seed=0x2222).build(instrs2)

        chains1 = [i.meta["ch"] for i in instrs1]
        chains2 = [i.meta["ch"] for i in instrs2]
        self.assertNotEqual(chains1, chains2)

    def test_emit_runtime_valid_python(self):
        import ast
        try:
            ast.parse(IntegrityChainBuilder.emit_runtime())
        except SyntaxError as e:
            self.fail(f"emit_runtime has syntax error: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
