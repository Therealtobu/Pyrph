import sys
sys.path.insert(0, '.')
import unittest
from vm.resolver_v2 import OpcodeResolverV2


class TestResolverV2(unittest.TestCase):

    def test_single_roundtrip(self):
        r = OpcodeResolverV2(key=0xDEAD1234)
        for real_op in [0x1A, 0x2C, 0x3E, 0x52, 0x00, 0xFF]:
            snap = r.snapshot()
            enc  = r.encode(real_op)
            r.restore(snap)
            got  = r.resolve(enc) & 0xFF
            self.assertEqual(got, real_op & 0xFF,
                f"op={real_op:#x} enc={enc:#x} got={got:#x}")

    def test_sequential_roundtrip(self):
        key    = 0xCAFEBABE
        ops_in = [0x1A, 0x0E, 0x10, 0x52, 0x54, 0x2C, 0x3C]
        # encode phase
        enc_r   = OpcodeResolverV2(key=key)
        encoded = []
        for op in ops_in:
            enc = enc_r.encode(op)
            encoded.append(enc)
            enc_r.resolve(enc)   # advance state
        # decode phase
        dec_r   = OpcodeResolverV2(key=key)
        ops_out = [dec_r.resolve(e) & 0xFF for e in encoded]
        self.assertEqual([o & 0xFF for o in ops_in], ops_out)

    def test_state_mutates(self):
        r = OpcodeResolverV2(key=0x1111)
        states = set()
        for enc in range(25):
            states.add(r.state)
            r.resolve(enc)
        self.assertGreater(len(states), 20)

    def test_data_flow_affects_output(self):
        r1 = OpcodeResolverV2(key=0xABCD)
        r2 = OpcodeResolverV2(key=0xABCD)
        r2.feed_data(0x12345678)
        self.assertNotEqual(r1.resolve(0xDEAD), r2.resolve(0xDEAD))

    def test_prev_op_affects_output(self):
        r1 = OpcodeResolverV2(key=0x5555)
        r2 = OpcodeResolverV2(key=0x5555)
        r1.resolve(0xAAAA)   # drive r1 history
        self.assertNotEqual(r1.resolve(0x1234), r2.resolve(0x1234))

    def test_different_keys(self):
        r1 = OpcodeResolverV2(key=0x1111)
        r2 = OpcodeResolverV2(key=0x2222)
        self.assertNotEqual(r1.resolve(0xABCD), r2.resolve(0xABCD))


if __name__ == "__main__":
    unittest.main(verbosity=2)
