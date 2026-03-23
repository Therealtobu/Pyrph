import sys; sys.path.insert(0, '.')
import unittest
from ..ir_obf.mutating_const_pool import MutatingConstPool

exec(MutatingConstPool.emit_runtime())   # defines _MCP


class TestMCP(unittest.TestCase):

    def _make_pool(self, consts: dict, seed=0xABCD1234):
        mcp = MutatingConstPool(seed=seed)
        enc, masks, s = mcp.encode_table(consts)
        return _MCP(enc, masks, s)  # noqa

    def test_roundtrip_basic(self):
        consts = {0: 42, 1: 100, 2: -7, 3: 0, 4: 0xFFFF}
        pool   = self._make_pool(consts)
        for idx, expected in consts.items():
            self.assertEqual(pool.get(idx), expected, f"idx={idx}")

    def test_non_int_passthrough(self):
        consts = {0: "hello", 1: None}
        pool   = self._make_pool(consts)
        self.assertEqual(pool.get(0), "hello")
        self.assertIsNone(pool.get(1))

    def test_re_encode_after_read(self):
        """Raw value changes after get() but decoded value stays correct."""
        consts = {0: 999}
        pool   = self._make_pool(consts)
        raw_before = pool._pool[0]
        val1       = pool.get(0)
        raw_after  = pool._pool[0]
        val2       = pool.get(0)
        self.assertNotEqual(raw_before, raw_after, "raw should change")
        self.assertEqual(val1, 999)
        self.assertEqual(val2, 999)

    def test_state_changes_after_get(self):
        consts = {i: i * 10 for i in range(10)}
        pool   = self._make_pool(consts)
        states = set()
        for i in range(10):
            states.add(pool._state)
            pool.get(i)
        self.assertGreater(len(states), 7)

    def test_access_history_changes_state(self):
        consts = {i: i for i in range(15)}
        p1 = self._make_pool(consts, seed=0x3333)
        p2 = self._make_pool(consts, seed=0x3333)
        for i in range(10):       p1.get(i)
        for i in range(9, -1, -1): p2.get(i)
        self.assertNotEqual(p1._state, p2._state)

    def test_different_seeds_different_raw(self):
        consts = {0: 12345}
        mcp1 = MutatingConstPool(seed=0xAAAA)
        mcp2 = MutatingConstPool(seed=0xBBBB)
        enc1, _, _ = mcp1.encode_table(consts)
        enc2, _, _ = mcp2.encode_table(consts)
        self.assertNotEqual(enc1[0], enc2[0])

    def test_large_table_256(self):
        consts = {i: (i * 997 + 13) % (2**16) for i in range(256)}
        pool   = self._make_pool(consts, seed=0xDEADBEEF)
        for idx, expected in consts.items():
            self.assertEqual(pool.get(idx), expected, f"idx={idx}")

    def test_repeated_reads_always_correct(self):
        """get() called 3× on same index must always return same value."""
        consts = {0: 777}
        pool   = self._make_pool(consts)
        for _ in range(3):
            self.assertEqual(pool.get(0), 777)

    def test_negative_integers(self):
        consts = {0: -1, 1: -255, 2: -(2**15)}
        pool   = self._make_pool(consts)
        for idx, expected in consts.items():
            self.assertEqual(pool.get(idx), expected, f"idx={idx}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
