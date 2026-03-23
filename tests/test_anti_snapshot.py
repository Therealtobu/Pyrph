import sys; sys.path.insert(0, '.')
import unittest, ast
from ..vm.anti_snapshot import AntiSnapshot

exec(AntiSnapshot.emit_runtime(period=4))   # noqa


class _FakeRes:
    def __init__(self):
        self.data_flow = 0


class TestAntiSnapshot(unittest.TestCase):

    def test_tick_changes_data_flow(self):
        r1 = _FakeRes(); r2 = _FakeRes()
        initial = r1.data_flow
        for i in range(4):
            _anti_snap_tick(r1, r2, i)  # noqa
        self.assertNotEqual(r1.data_flow, initial)

    def test_both_resolvers_affected(self):
        r1 = _FakeRes(); r2 = _FakeRes()
        for i in range(4):
            _anti_snap_tick(r1, r2, i)  # noqa
        self.assertNotEqual(r1.data_flow, 0)
        self.assertNotEqual(r2.data_flow, 0)

    def test_no_change_between_periods(self):
        """data_flow stays same on ic=1,2,3 (period=4, no pid period hit)."""
        r1 = _FakeRes(); r2 = _FakeRes()
        r1.data_flow = 0xABCD; r2.data_flow = 0xABCD
        for ic in [1, 2, 3]:
            _anti_snap_tick(r1, r2, ic)  # noqa
        self.assertEqual(r1.data_flow, 0xABCD)
        self.assertEqual(r2.data_flow, 0xABCD)

    def test_does_not_raise(self):
        r1 = _FakeRes(); r2 = _FakeRes()
        for ic in range(200):
            try:
                _anti_snap_tick(r1, r2, ic)  # noqa
            except Exception as e:
                self.fail(f"raised at ic={ic}: {e}")

    def test_emit_runtime_valid_python(self):
        try:
            ast.parse(AntiSnapshot.emit_runtime())
        except SyntaxError as e:
            self.fail(f"syntax error: {e}")

    def test_emit_tick_call_string(self):
        s = AntiSnapshot.emit_vm3_tick_call()
        self.assertIn("_anti_snap_tick", s)
        self.assertIn("self.r1", s)
        self.assertIn("self.r2", s)
        self.assertIn("self.pc", s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
