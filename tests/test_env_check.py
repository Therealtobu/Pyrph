import sys; sys.path.insert(0, '.')
import unittest
from ..vm.env_check import EnvCheck

exec(EnvCheck.emit_runtime())   # defines _pyrph_env_ok, _pyrph_poison_state  # noqa


class TestEnvCheck(unittest.TestCase):

    def test_clean_env_returns_true(self):
        """Normal execution → no tracer/profiler → should return True."""
        # Ensure no tracer set by test runner itself
        import sys as _sys
        _old = _sys.gettrace()
        _sys.settrace(None)
        try:
            result = _pyrph_env_ok()  # noqa
            self.assertTrue(result, "clean env should return True")
        finally:
            _sys.settrace(_old)

    def test_tracer_detected(self):
        """sys.settrace → should return False."""
        import sys as _sys
        _pyrph_ok = _pyrph_env_ok  # noqa  – capture before settrace
        _sys.settrace(lambda *a: None)
        try:
            result = _pyrph_ok()
            self.assertFalse(result, "tracer should be detected")
        finally:
            _sys.settrace(None)

    def test_profiler_detected(self):
        """sys.setprofile → should return False."""
        import sys as _sys
        _sys.setprofile(lambda *a: None)
        try:
            result = _pyrph_env_ok()  # noqa
            self.assertFalse(result, "profiler should be detected")
        finally:
            _sys.setprofile(None)

    def test_poison_state_changes_keys(self):
        """_pyrph_poison_state must XOR both key and state."""
        class _FakeRes:
            key   = 0x1234
            state = 0xABCD

        r = _FakeRes()
        _pyrph_poison_state(r, 0xDEADF00D)  # noqa
        self.assertEqual(r.key,   0x1234 ^ 0xDEADF00D)
        self.assertEqual(r.state, 0xABCD ^ 0xDEADF00D)

    def test_poison_idempotent_on_error(self):
        """poison_state must not raise even with broken object."""
        class _Bad:
            @property
            def key(self): raise RuntimeError("broken")

        try:
            _pyrph_poison_state(_Bad(), 0x1234)  # noqa
        except Exception as e:
            self.fail(f"poison_state raised unexpectedly: {e}")

    def test_emit_bootstrap_check_syntax(self):
        """emit_bootstrap_check output must be valid Python."""
        import ast
        code = EnvCheck.emit_bootstrap_check()
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.fail(f"bootstrap check has syntax error: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
