import sys; sys.path.insert(0, '.')
import unittest
from vm.frame_poison import FramePoisoner

exec(FramePoisoner.emit_runtime())   # defines _SS  # noqa


class TestSplitState(unittest.TestCase):

    def _make(self, size=16, s1=0xABCD, s2=0x1234):
        return _SS(size, s1, s2)  # noqa

    def test_write_read_integer(self):
        ss = self._make()
        ss.write(0, 42)
        self.assertEqual(ss.read_any(0), 42)

    def test_write_read_various(self):
        ss = self._make()
        for idx, val in enumerate([0, 1, -1, 255, 65535, 2**20, -999]):
            ss.write(idx, val)
            self.assertEqual(ss.read_any(idx), val, f"idx={idx} val={val}")

    def test_raw_storage_is_obfuscated(self):
        """Raw _a/_b must NOT equal plain value."""
        ss = self._make()
        ss.write(0, 12345)
        self.assertNotEqual(ss._a[0], 12345)
        self.assertNotEqual(ss._b[0], 12345)

    def test_non_int_passthrough(self):
        """Non-int objects stored and retrieved correctly."""
        ss = self._make()
        obj = [1, 2, 3]
        ss.write(3, obj)
        self.assertIs(ss.read_any(3), obj)

    def test_tick_re_encodes_correctly(self):
        """After tick(), reading same index must still return original value."""
        ss = self._make()
        ss.write(0, 777)
        ss.tick(pc=1, last_op=0x1A)
        self.assertEqual(ss.read_any(0), 777,
            "value should survive tick/re-encode")

    def test_multiple_ticks(self):
        """Value survives 50 consecutive ticks."""
        ss = self._make()
        ss.write(5, 99)
        for i in range(50):
            ss.tick(pc=i, last_op=i * 3)
        self.assertEqual(ss.read_any(5), 99)

    def test_different_seeds_different_raw(self):
        """Same value, different seeds → different raw _a bytes."""
        ss1 = self._make(s1=0x1111, s2=0x2222)
        ss2 = self._make(s1=0x3333, s2=0x4444)
        ss1.write(0, 42)
        ss2.write(0, 42)
        self.assertNotEqual(ss1._a[0], ss2._a[0],
            "different seeds should produce different raw encoding")

    def test_tick_changes_raw(self):
        """Raw storage bytes must change after tick (re-keyed)."""
        ss = self._make()
        ss.write(0, 42)
        raw_before = (ss._a[0], ss._b[0])
        ss.tick(pc=5, last_op=0x2A)
        raw_after  = (ss._a[0], ss._b[0])
        self.assertNotEqual(raw_before, raw_after,
            "raw encoding should change after tick")

    def test_write_zero(self):
        ss = self._make()
        ss.write(2, 0)
        self.assertEqual(ss.read_any(2), 0)

    def test_overwrite(self):
        """Overwriting a slot must give the new value."""
        ss = self._make()
        ss.write(1, 100)
        ss.write(1, 200)
        self.assertEqual(ss.read_any(1), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
