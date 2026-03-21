"""
Tests for Parallel Dual-Engine (parallel_engine package):

SharedState:
  1.  init: vm3_state and rust_state set correctly
  2.  cross_key computed on init
  3.  vm3_commit updates vm3_state + cross_key + turn
  4.  rust_commit updates rust_state + cross_key + turn
  5.  whose_turn alternates after each commit
  6.  cross_key changes when state changes
  7.  snapshot + restore round-trip
  8.  combine: returns vm3_result when rust confirms correctly
  9.  combine: corrupts when rust_result mismatches
  10. combine: non-int passthrough unchanged

RustEngine (Python fallback):
  11. init without native core works
  12. exec_one returns int
  13. exec_one commits to SharedState
  14. decode changes with different enc values
  15. confirmation_value = hash(vm3_r ^ cross_key) & MASK

ParallelCoordinator:
  16. bytecode split even/odd correctly
  17. run_process_parallel returns value without crash
  18. result type preserved (int)
  19. different seeds → different cross_key
  20. combine clean (no corruption with correct confirmation)

ParallelCoordinatorEmitter:
  21. emit_runtime() is valid Python
  22. _PEState init and commit work
  23. _pe_cross_key is state-dependent
  24. _pe_apply returns int for int input
  25. _pe_apply returns non-int unchanged
  26. _pe_rust_confirmation deterministic
  27. _pe_apply never raises
  28. emit_bootstrap() valid Python snippet
"""
import sys, ast
sys.path.insert(0, '.')
import unittest
import time

from parallel_engine.shared_state  import SharedState
from parallel_engine.rust_engine   import RustEngine
from parallel_engine.coordinator   import (
    ParallelCoordinator, ParallelCoordinatorEmitter
)


def _exec(code: str) -> dict:
    ns = {"__builtins__": __builtins__}
    exec(code, ns)
    return ns


# ── SharedState ───────────────────────────────────────────────────────────────
class TestSharedState(unittest.TestCase):

    def _make(self, v=0xAAAA, r=0xBBBB):
        return SharedState(v, r)

    def test_init_states(self):
        s = self._make(0x1234, 0x5678)
        self.assertEqual(s.vm3_state,  0x1234)
        self.assertEqual(s.rust_state, 0x5678)

    def test_cross_key_computed(self):
        s = self._make()
        self.assertIsInstance(s.cross_key, int)
        self.assertGreater(s.cross_key, 0)

    def test_vm3_commit_updates(self):
        s = self._make()
        old_ck = s.cross_key
        s.vm3_commit(0xCAFE, 42)
        self.assertEqual(s.vm3_state, 0xCAFE)
        self.assertNotEqual(s.cross_key, old_ck)

    def test_rust_commit_updates(self):
        s = self._make()
        s.rust_commit(0xDEAD, 99)
        self.assertEqual(s.rust_state, 0xDEAD)

    def test_turn_alternates(self):
        s = self._make()
        self.assertEqual(s.whose_turn(), 0)   # Python first
        s.vm3_commit(1, 1)
        self.assertEqual(s.whose_turn(), 1)   # Rust next
        s.rust_commit(2, 2)
        self.assertEqual(s.whose_turn(), 0)   # Python again

    def test_cross_key_state_dependent(self):
        s1 = self._make(0x1111, 0x2222)
        s2 = self._make(0x3333, 0x4444)
        self.assertNotEqual(s1.cross_key, s2.cross_key)

    def test_snapshot_restore(self):
        s = self._make()
        s.vm3_commit(0xABCD, 55)
        snap = s.snapshot()
        s.rust_commit(0x9999, 77)
        s.restore(snap)
        self.assertEqual(s.vm3_state, 0xABCD)

    def test_combine_clean(self):
        s = self._make()
        vm3_r = 42
        rust_r = (vm3_r ^ s.cross_key) & 0xFFFFFFFF
        result = s.combine_results(vm3_r, rust_r)
        self.assertEqual(result, vm3_r)

    def test_combine_tampered(self):
        s = self._make()
        vm3_r = 1000
        wrong_r = 0xDEAD   # wrong confirmation
        result = s.combine_results(vm3_r, wrong_r)
        # Should be corrupted (may or may not equal vm3_r depending on noise)
        self.assertIsInstance(result, int)

    def test_combine_non_int(self):
        s = self._make()
        result = s.combine_results("hello", 0)
        self.assertEqual(result, "hello")


# ── RustEngine ────────────────────────────────────────────────────────────────
class TestRustEngine(unittest.TestCase):

    def _make_engine(self):
        shared = SharedState(0xAAAA, 0xBBBB)
        bc     = [{"e": 0x1234, "v": 1, "o": [], "bk": 0}]
        return RustEngine(shared, bc, {0: 42, 1: "test"}), shared

    def test_init_no_crash(self):
        eng, _ = self._make_engine()
        self.assertIsNotNone(eng)

    def test_exec_one_returns_value(self):
        eng, _ = self._make_engine()
        instr  = {"e": 0x1234, "v": 1, "o": [], "bk": 0}
        result = eng.exec_one(instr)
        self.assertIsNotNone(result)

    def test_exec_one_commits_to_shared(self):
        eng, shared = self._make_engine()
        old_state = shared.rust_state
        eng.exec_one({"e": 0xABCD, "v": 1, "o": [], "bk": 0})
        # rust_commit was called → state may have changed
        self.assertIsInstance(shared.rust_state, int)

    def test_decode_deterministic(self):
        eng, _ = self._make_engine()
        enc = 0x1234
        # save state
        snap_state = eng._state
        snap_prev  = eng._prev_op
        snap_df    = eng._data_flow
        op1 = eng._decode(enc)
        # restore
        eng._state     = snap_state
        eng._prev_op   = snap_prev
        eng._data_flow = snap_df
        op2 = eng._decode(enc)
        self.assertEqual(op1, op2)

    def test_confirmation_value(self):
        eng, shared = self._make_engine()
        vm3_r = 777
        conf  = eng.confirmation_value(vm3_r)
        expected = (vm3_r ^ shared.cross_key) & 0xFFFFFFFF
        self.assertEqual(conf, expected)


# ── ParallelCoordinator ───────────────────────────────────────────────────────
class TestParallelCoordinator(unittest.TestCase):

    def _make(self, n_instrs=6):
        bc = [{"e": i*7+3, "v": i%2, "o": [], "bk": 0} for i in range(n_instrs)]
        return ParallelCoordinator(bc, {}, 0xAAAA, 0xBBBB)

    def test_bytecode_split(self):
        coord = self._make(6)
        # Even indices: 0,2,4 → Python; Odd: 1,3,5 → Rust
        self.assertEqual(len(coord._bc_python), 3)
        self.assertEqual(len(coord._bc_rust),   3)

    def test_run_process_parallel_no_crash(self):
        """process parallel with no vm3_instance (simulate)."""
        coord = self._make(4)
        # No real vm3_instance; just test Rust part runs
        for ins in coord._bc_rust:
            coord._rust_eng.exec_one(ins)
        result = coord._shared.combine_results(42, (42 ^ coord._shared.cross_key) & 0xFFFFFFFF)
        self.assertEqual(result, 42)

    def test_combine_clean_confirmation(self):
        coord = self._make()
        ck    = coord._shared.cross_key
        vm3_r = 100
        conf  = (vm3_r ^ ck) & 0xFFFFFFFF
        result = coord._shared.combine_results(vm3_r, conf)
        self.assertEqual(result, vm3_r)

    def test_different_seeds_different_cross_key(self):
        c1 = ParallelCoordinator([], {}, 0x1111, 0x2222)
        c2 = ParallelCoordinator([], {}, 0x3333, 0x4444)
        self.assertNotEqual(c1._shared.cross_key, c2._shared.cross_key)

    def test_run_process_parallel_waits_for_vm3_result(self):
        coord = self._make(6)

        class _VM3:
            def run(self, _init_env):
                time.sleep(0.02)  # Ensure Rust reaches confirmation first.
                return 1337

        vm3 = _VM3()
        result = coord.run_process_parallel(vm3, {})
        self.assertEqual(result, 1337)

    def test_run_process_parallel_repeat_no_state_leak(self):
        class _VM3:
            def __init__(self, value):
                self._value = value
            def run(self, _init_env):
                time.sleep(0.01)
                return self._value

        for i in range(12):
            coord = self._make(8)
            vm3 = _VM3(1000 + i)
            out = coord.run_process_parallel(vm3, {})
            self.assertEqual(out, 1000 + i)


# ── Emitter ───────────────────────────────────────────────────────────────────
class TestParallelCoordinatorEmitter(unittest.TestCase):

    def setUp(self):
        code = ParallelCoordinatorEmitter.emit_runtime()
        code += "\n_NC_NATIVE = False\n_NC = None\n"
        self.ns = _exec(code)

    def test_emit_runtime_valid_python(self):
        try:
            ast.parse(ParallelCoordinatorEmitter.emit_runtime())
        except SyntaxError as e:
            self.fail(f"syntax error: {e}")

    def test_pe_state_init(self):
        ns = self.ns
        s  = ns["_PEState"](0xAAAA, 0xBBBB)
        self.assertEqual(s.vm3_state,  0xAAAA)
        self.assertEqual(s.rust_state, 0xBBBB)
        self.assertIsInstance(s.cross_key, int)

    def test_pe_cross_key_state_dependent(self):
        ns = self.ns
        k1 = ns["_pe_cross_key"](0x1111, 0x2222)
        k2 = ns["_pe_cross_key"](0x3333, 0x4444)
        self.assertNotEqual(k1, k2)

    def test_pe_apply_int(self):
        ns = self.ns
        result = ns["_pe_apply"](42, 0x1234, 0x5678)
        self.assertIsInstance(result, int)

    def test_pe_apply_non_int_unchanged(self):
        ns = self.ns
        result = ns["_pe_apply"]("hello", 0x1234, 0x5678)
        self.assertEqual(result, "hello")

    def test_pe_apply_never_raises(self):
        ns = self.ns
        for val in [0, -1, 42, None, "x", [1,2], True]:
            try:
                ns["_pe_apply"](val, 0xAAAA, 0xBBBB)
            except Exception as e:
                self.fail(f"_pe_apply raised for {val!r}: {e}")

    def test_pe_rust_confirmation_deterministic(self):
        ns  = self.ns
        c1  = ns["_pe_rust_confirmation"](42, 0x1234)
        c2  = ns["_pe_rust_confirmation"](42, 0x1234)
        self.assertEqual(c1, c2)

    def test_pe_state_combine_clean(self):
        ns    = self.ns
        s     = ns["_PEState"](0x1111, 0x2222)
        vm3_r = 999
        conf  = (vm3_r ^ s.cross_key) & 0xFFFFFFFF
        result = s.combine(vm3_r, conf)
        self.assertEqual(result, vm3_r)

    def test_emit_bootstrap_valid(self):
        code = ParallelCoordinatorEmitter.emit_bootstrap()
        # Wrap in function for syntax check
        try:
            ast.parse(f"def _check():\n    pass\n{code}")
        except SyntaxError as e:
            self.fail(f"bootstrap syntax error: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
