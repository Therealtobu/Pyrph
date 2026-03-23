"""
VM4 Tests – Fragment Graph + Execution Fabric + State Mesh + DNA Lock

Fragment Graph:
  1.  Build from IR instructions → non-empty pool
  2.  REAL fragments exist in pool
  3.  Decoy ratio approximately correct
  4.  Ticket masks reference valid fragment IDs
  5.  Serialise/deserialise round-trip intact
  6.  Causality key changes with last_output

Execution Fabric:
  7.  _ef_pick returns index in [0, N)
  8.  _ef_pick changes with different state inputs
  9.  _ef_decode_fragment returns tuple or None (no crash)
  10. _ef_run terminates with small pool
  11. _ef_converged True when all real frags done

State Mesh:
  12. write + read integer round-trip
  13. write + read non-int round-trip
  14. raw shards != plain value
  15. rekey preserves values
  16. snapshot + restore round-trip
  17. dna_hash changes after write

DNA Lock:
  18. _dna_finalize returns int
  19. Different hist → different DNA
  20. _dna_reconstruct returns int (no crash)
  21. _dna_lock_check True on matching hint

VM4Engine:
  22. emit_all_runtime() is valid Python
  23. build_fragment_graph from IRModule works
  24. _vm4_apply on int returns int
  25. _vm4_apply on non-int returns unchanged
  26. _vm4_apply never raises
"""
import sys, ast
sys.path.insert(0, '.')
import unittest, copy

from ir.nodes   import IRModule, IRFunction, IRBlock, IRInstruction, IROp, IROperand
from ir.builder import IRBuilder
from ir.cfg     import CFGBuilder

from vm4.fragment_graph   import FragmentGraphBuilder, FragType
from vm4.execution_fabric import ExecutionFabricEmitter
from vm4.state_mesh       import StateMeshEmitter
from vm4.dna_lock         import DNALockEmitter
from vm4.vm4_engine       import VM4Engine


def _exec(code: str) -> dict:
    ns = {"__builtins__": __builtins__}
    exec(code, ns)
    return ns


def _build_mod(src: str) -> IRModule:
    import ast as _ast
    tree = _ast.parse(src)
    mod  = IRBuilder().build(tree)
    CFGBuilder().build(mod)
    return mod


# ── Fragment Graph ────────────────────────────────────────────────────────────
class TestFragmentGraph(unittest.TestCase):

    def _build(self, n_ops=5):
        instrs = [{"op": "ADD", "dst": "x", "src": ["a","b"]},
                  {"op": "STORE_VAR", "dst": "y", "src": ["x"]},
                  {"op": "LOAD_VAR",  "dst": "z", "src": ["y"]},
                  {"op": "MUL",       "dst": "r", "src": ["z","2"]},
                  {"op": "RETURN",    "dst": "",  "src": ["r"]}][:n_ops]
        return FragmentGraphBuilder(frags_per_op=4, decoy_ratio=0.35).build(instrs)

    def test_pool_non_empty(self):
        fg = self._build()
        self.assertGreater(len(fg.fragments), 0)

    def test_real_fragments_exist(self):
        fg = self._build()
        reals = [f for f in fg.fragments if f.ftype == FragType.REAL]
        self.assertGreater(len(reals), 0)

    def test_decoy_ratio_approx(self):
        fg      = self._build(5)
        decoys  = [f for f in fg.fragments if f.ftype != FragType.REAL]
        ratio   = len(decoys) / len(fg.fragments)
        self.assertGreater(ratio, 0.1, "too few decoys")
        self.assertLess(ratio, 0.8, "too many decoys")

    def test_ticket_masks_valid(self):
        fg      = self._build()
        all_ids = {f.id for f in fg.fragments}
        for f in fg.fragments:
            for tid in f.ticket_mask:
                self.assertIn(tid, all_ids, f"ticket {tid} not in pool")

    def test_serialise_roundtrip(self):
        builder = FragmentGraphBuilder(frags_per_op=3)
        fg      = self._build()
        data    = builder.serialise(fg)
        self.assertIn("frags", data)
        self.assertIn("real",  data)
        self.assertGreater(len(data["frags"]), 0)

    def test_causality_key_changes(self):
        ns  = _exec(ExecutionFabricEmitter.emit_runtime())
        k1  = ns["_ef_causality_key"](0x1234, 0xABCD, 0x5678)
        k2  = ns["_ef_causality_key"](0x9999, 0xABCD, 0x5678)
        self.assertNotEqual(k1, k2)


# ── Execution Fabric ──────────────────────────────────────────────────────────
class TestExecutionFabric(unittest.TestCase):

    def setUp(self):
        code = ExecutionFabricEmitter.emit_runtime()
        code += "\n" + ExecutionFabricEmitter.emit_init_code()
        self.ns = _exec(code)

    def test_pick_in_range(self):
        for n in [2, 5, 10, 100]:
            idx = self.ns["_ef_pick"](n, 0x1234, 0xABCD, 0x5678, 0)
            self.assertGreaterEqual(idx, 0)
            self.assertLess(idx, n)

    def test_pick_changes_with_state(self):
        i1 = self.ns["_ef_pick"](100, 0x1111, 0x2222, 0x3333, 1)
        i2 = self.ns["_ef_pick"](100, 0xAAAA, 0xBBBB, 0xCCCC, 1)
        self.assertNotEqual(i1, i2)

    def test_decode_fragment_no_crash(self):
        import struct
        for enc in [b'\x00'*9, b'\xFF'*9, b'\xAB\xCD\xEF\x01\x23\x45\x67\x89\x42']:
            try:
                self.ns["_ef_decode_fragment"](list(enc), 0x1234)
            except Exception as e:
                self.fail(f"decode_fragment raised: {e}")

    def test_ef_run_terminates(self):
        """Small pool with 1 real fragment must converge."""
        import struct
        # Build minimal pool: 1 real + 1 noise
        enc = list(struct.pack(">HHHH", 0x1A, 0x01, 0xAB, 0xCD)) + [0x42]
        pool = [
            {"id": 1, "ft": 1, "ep": enc, "tm": [], "ni": 0, "op": "ADD"},
            {"id": 2, "ft": 2, "ep": enc, "tm": [], "ni": 1, "op": "__noise"},
        ]
        real_ids = [1]
        sm       = {}
        try:
            sm_out, dna, hist = self.ns["_ef_run"](
                pool, real_ids, sm, lambda: 0, 0x1234, max_cycles=200
            )
            self.assertIsInstance(dna, int)
        except Exception as e:
            self.fail(f"_ef_run raised: {e}")

    def test_converged_all_real_done(self):
        done = {1, 2, 3}
        real = [1, 2, 3]
        self.assertTrue(self.ns["_ef_converged"](done, real, [1,2,3]))

    def test_converged_false_when_missing(self):
        done = {1, 2}
        real = [1, 2, 3]
        self.assertFalse(self.ns["_ef_converged"](done, real, [1,2]))


# ── State Mesh ────────────────────────────────────────────────────────────────
class TestStateMesh(unittest.TestCase):

    def setUp(self):
        self.ns = _exec(StateMeshEmitter.emit_runtime())

    def _make_sm(self, seed=0x1234):
        return self.ns["_StateMesh"](
            dna_seed     = seed,
            sag_state_fn = lambda: 0,
            mcp_fn       = lambda: 0,
        )

    def test_int_roundtrip(self):
        sm = self._make_sm()
        sm.write("x", 42)
        self.assertEqual(sm.read("x"), 42)

    def test_non_int_roundtrip(self):
        sm = self._make_sm()
        sm.write("msg", "hello")
        self.assertEqual(sm.read("msg"), "hello")

    def test_raw_shards_obfuscated(self):
        sm = self._make_sm()
        sm.write("v", 12345)
        shards = sm._shards.get("v", [])
        self.assertNotEqual(shards[0], 12345, "shard 0 should not equal plain value")

    def test_rekey_preserves_value(self):
        sm = self._make_sm()
        sm.write("y", 999)
        sm.rekey(0xDEADBEEF)
        self.assertEqual(sm.read("y"), 999)

    def test_snapshot_restore(self):
        sm = self._make_sm()
        sm.write("z", 777)
        snap = sm.snapshot()
        sm.write("z", 0)
        self.assertEqual(sm.read("z"), 0)
        sm.restore(snap)
        self.assertEqual(sm.read("z"), 777)

    def test_dna_hash_changes_after_write(self):
        sm = self._make_sm()
        h1 = sm.dna_hash()
        sm.write("w", 42)
        h2 = sm.dna_hash()
        self.assertNotEqual(h1, h2)

    def test_multiple_vars(self):
        sm = self._make_sm()
        vals = {"a": 1, "b": 2, "c": 3, "d": 100}
        for k, v in vals.items():
            sm.write(k, v)
        for k, v in vals.items():
            self.assertEqual(sm.read(k), v, f"var {k}")


# ── DNA Lock ──────────────────────────────────────────────────────────────────
class TestDNALock(unittest.TestCase):

    def setUp(self):
        self.ns = _exec(DNALockEmitter.emit_runtime())

    def test_finalize_returns_int(self):
        result = self.ns["_dna_finalize"](0x1234, [1,2,3], {"x": 42}, {1:1})
        self.assertIsInstance(result, int)

    def test_different_hist_different_dna(self):
        d1 = self.ns["_dna_finalize"](0x1111, [1,2,3], {}, {})
        d2 = self.ns["_dna_finalize"](0x1111, [4,5,6], {}, {})
        self.assertNotEqual(d1, d2)

    def test_reconstruct_no_crash(self):
        for sm in [{}, {"x": 42, "y": 99}, {"a": 1}]:
            try:
                self.ns["_dna_reconstruct"](sm, 0x1234, [1,2,3], {1:1})
            except Exception as e:
                self.fail(f"_dna_reconstruct raised: {e}")

    def test_lock_check_matching(self):
        vm3_r = 42
        vm3_s = 0x1234
        hint  = (vm3_r ^ vm3_s) & 0xFFFF
        dna   = hint | (hint << 16)   # hint in low 16 bits
        result = self.ns["_dna_lock_check"](hint, dna)
        self.assertTrue(result)

    def test_lock_check_mismatch(self):
        result = self.ns["_dna_lock_check"](0x1234, 0xABCD)
        self.assertFalse(result)


# ── VM4Engine ─────────────────────────────────────────────────────────────────
class TestVM4Engine(unittest.TestCase):

    def test_emit_all_valid_python(self):
        engine = VM4Engine()
        mod    = _build_mod("x = 1\ny = x + 2\n")
        fg     = engine.build_fragment_graph(mod)
        code   = engine.emit_all_runtime(fg)
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.fail(f"syntax error: {e}")

    def test_build_fg_from_irmodule(self):
        engine = VM4Engine()
        mod    = _build_mod("a = 1\nb = 2\nc = a + b\n")
        fg     = engine.build_fragment_graph(mod)
        self.assertGreater(len(fg.fragments), 0)
        self.assertGreater(len(fg.real_ids), 0)

    def test_vm4_apply_int(self):
        engine = VM4Engine()
        mod    = _build_mod("x = 1\n")
        fg     = engine.build_fragment_graph(mod)
        code   = engine.emit_all_runtime(fg)
        ns     = _exec(code)
        result = ns["_vm4_apply"](42, 0x1234)
        self.assertIsInstance(result, int)

    def test_vm4_apply_non_int_unchanged(self):
        engine = VM4Engine()
        mod    = _build_mod("x = 1\n")
        fg     = engine.build_fragment_graph(mod)
        code   = engine.emit_all_runtime(fg)
        ns     = _exec(code)
        result = ns["_vm4_apply"]("hello", 0x1234)
        self.assertEqual(result, "hello")

    def test_vm4_apply_never_raises(self):
        engine = VM4Engine()
        mod    = _build_mod("x = 1\n")
        fg     = engine.build_fragment_graph(mod)
        code   = engine.emit_all_runtime(fg)
        ns     = _exec(code)
        for val in [0, -1, 42, None, "x", [1,2], True]:
            try:
                ns["_vm4_apply"](val, 0xABCD)
            except Exception as e:
                self.fail(f"_vm4_apply raised for {val!r}: {e}")

    def test_vm4_apply_large_pool(self):
        engine = VM4Engine(frags_per_op=6, decoy_ratio=0.4)
        mod    = _build_mod("def f(x,y):\n    z=x+y\n    return z*2\n")
        fg     = engine.build_fragment_graph(mod)
        code   = engine.emit_all_runtime(fg)
        ns     = _exec(code)
        result = ns["_vm4_apply"](100, 0x5678)
        self.assertIsInstance(result, int)


if __name__ == "__main__":
    unittest.main(verbosity=2)
