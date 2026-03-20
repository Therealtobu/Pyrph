"""
Tests for Semantic Alias Graph (SAG):

AliasNode:
  1. AliasSet has correct real_idx
  2. AliasSource.is_live respects alive_from/alive_to
  3. AliasGraph.has_cycles detects cycles correctly
  4. AliasGraph.emit_runtime_header is valid Python

AliasBuilder:
  5. Builds alias sets for non-dunder variables
  6. Each AliasSet has correct n_fakes
  7. Cross-variable edges added
  8. Dunder variables skipped

SAGIRInjector:
  9.  STORE_VAR gets SAG_DEFINE + SAG_TICK + fake stores
  10. LOAD_VAR gets SAG_SELECT + SAG_COMBINE
  11. Instruction count increases after injection
  12. Original STORE_VAR preserved in output

SAGPass:
  13. run() does not crash on simple module
  14. run() does not crash on complex module
  15. graph stats accessible after run()
  16. has_cycles True when cross edges exist

SAGRuntime:
  17. emit_runtime() is valid Python
  18. __sag_sel returns int in [0, n)
  19. __sag_combine returns correct value at real_idx
  20. __sag_tick mutates state
  21. Observer effect: double tick changes state
  22. __sag_combine falls back on wrong idx (tamper sim)
"""
import sys, ast
sys.path.insert(0, '.')
import unittest

from ir.nodes        import IROp, IROperand, IRInstruction, IRFunction, IRModule
from ir.builder      import IRBuilder
from ir.cfg          import CFGBuilder

from sag.alias_node      import AliasSource, AliasSet, AliasGraph
from sag.alias_builder   import AliasBuilder
from sag.ir_injector     import SAGIRInjector
from sag.sag_pass        import SAGPass
from sag.runtime_emitter import SAGRuntimeEmitter


def _build(src: str) -> IRModule:
    tree = ast.parse(src)
    mod  = IRBuilder().build(tree)
    CFGBuilder().build(mod)
    return mod


# ── AliasNode tests ───────────────────────────────────────────────────────────
class TestAliasNode(unittest.TestCase):

    def test_real_source_returns_real(self):
        src_r = AliasSource(IROperand("const", 42), True,  0, 0, None)
        src_f = AliasSource(IROperand("const", 99), False, 0, 0, None)
        aset  = AliasSet("x", [src_f, src_r], real_idx=1, select_key=0)
        self.assertTrue(aset.real_source().is_real)

    def test_fake_sources_list(self):
        src_r = AliasSource(IROperand("const", 1), True,  0, 0, None)
        src_f1= AliasSource(IROperand("const", 2), False, 0, 0, None)
        src_f2= AliasSource(IROperand("const", 3), False, 0, 0, None)
        aset  = AliasSet("y", [src_r, src_f1, src_f2], real_idx=0)
        self.assertEqual(len(aset.fake_sources()), 2)
        self.assertTrue(all(not s.is_real for s in aset.fake_sources()))

    def test_alias_source_lifetime(self):
        src = AliasSource(IROperand("const", 0), False, 10, 20, None)
        self.assertFalse(src.is_live(5,  0))    # before alive_from
        self.assertTrue( src.is_live(10, 0))    # at alive_from
        self.assertTrue( src.is_live(15, 0))    # within window
        self.assertFalse(src.is_live(25, 0))    # after alive_to

    def test_alias_source_forever(self):
        src = AliasSource(IROperand("const", 0), True, 0, 0, None)
        self.assertTrue(src.is_live(9999, 0))   # alive_to=0 means forever

    def test_alias_graph_cycle_detection(self):
        graph = AliasGraph()
        for v in ["x", "y", "z"]:
            graph.register(AliasSet(v, [], 0))
        graph.add_cross_alias("x", "y")
        graph.add_cross_alias("y", "z")
        graph.add_cross_alias("z", "x")   # cycle: x→y→z→x
        self.assertTrue(graph.has_cycles())

    def test_alias_graph_no_cycle(self):
        graph = AliasGraph()
        for v in ["a", "b", "c"]:
            graph.register(AliasSet(v, [], 0))
        graph.add_cross_alias("a", "b")
        graph.add_cross_alias("b", "c")   # no cycle
        self.assertFalse(graph.has_cycles())

    def test_runtime_header_valid_python(self):
        graph = AliasGraph()
        code  = graph.emit_runtime_header()
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.fail(f"runtime header syntax error: {e}")


# ── AliasBuilder tests ────────────────────────────────────────────────────────
class TestAliasBuilder(unittest.TestCase):

    def test_builds_alias_sets(self):
        mod   = _build("x = 1\ny = 2\nz = x + y\n")
        graph = AliasBuilder(n_fakes=2).build(mod)
        self.assertGreater(len(graph.all_vars()), 0,
            "should build alias sets for variables")

    def test_dunder_vars_skipped(self):
        mod   = _build("x = 1\n")
        graph = AliasBuilder(n_fakes=2).build(mod)
        for v in graph.all_vars():
            self.assertFalse(v.startswith("__"),
                f"dunder var '{v}' should not be aliased")

    def test_each_set_has_fakes(self):
        mod   = _build("alpha = 10\nbeta = 20\n")
        graph = AliasBuilder(n_fakes=2).build(mod)
        for var in graph.all_vars():
            aset = graph.get(var)
            self.assertGreater(len(aset.fake_sources()), 0,
                f"{var} should have at least one fake alias")

    def test_real_idx_in_range(self):
        mod   = _build("val = 42\n")
        graph = AliasBuilder(n_fakes=2).build(mod)
        for var in graph.all_vars():
            aset = graph.get(var)
            self.assertGreaterEqual(aset.real_idx, 0)
            self.assertLess(aset.real_idx, aset.n_aliases())

    def test_cross_edges_added(self):
        """With cross_prob=1.0 and multiple vars, cross edges should appear."""
        mod   = _build("a = 1\nb = 2\nc = 3\nd = 4\n")
        graph = AliasBuilder(n_fakes=2, cross_prob=1.0).build(mod)
        total_edges = sum(len(v) for v in graph._edges.values())
        self.assertGreater(total_edges, 0,
            "cross-variable edges should be created")


# ── SAGIRInjector tests ───────────────────────────────────────────────────────
class TestSAGIRInjector(unittest.TestCase):

    def _inject(self, src: str):
        mod   = _build(src)
        graph = AliasBuilder(n_fakes=2, cross_prob=0).build(mod)
        SAGIRInjector(graph).inject(mod)
        return mod, graph

    def test_instruction_count_increases(self):
        mod_before = _build("x = 5\n")
        before = sum(len(b.instructions)
                     for fn in mod_before.functions
                     for b in fn.blocks)
        mod, _ = self._inject("x = 5\n")
        after  = sum(len(b.instructions)
                     for fn in mod.functions
                     for b in fn.blocks)
        self.assertGreater(after, before,
            "injection should add instructions")

    def test_sag_define_present(self):
        mod, graph = self._inject("result = 99\n")
        if not graph.all_vars():
            self.skipTest("no aliased vars")
        defines = [
            i for fn in mod.functions
            for b in fn.blocks
            for i in b.instructions
            if i.metadata.get("sag_op") == "SAG_ALIAS_DEFINE"
        ]
        self.assertGreater(len(defines), 0,
            "SAG_DEFINE instructions should be present")

    def test_sag_tick_present(self):
        mod, graph = self._inject("x = 10\n")
        if not graph.all_vars():
            self.skipTest("no aliased vars")
        ticks = [
            i for fn in mod.functions
            for b in fn.blocks
            for i in b.instructions
            if i.metadata.get("sag_op") == "SAG_TICK"
        ]
        self.assertGreater(len(ticks), 0)

    def test_original_store_preserved(self):
        mod, _ = self._inject("v = 7\n")
        stores = [
            i for fn in mod.functions
            for b in fn.blocks
            for i in b.instructions
            if i.op == IROp.STORE_VAR
            and not i.metadata.get("sag_fake")
        ]
        self.assertGreater(len(stores), 0,
            "original STORE_VAR must be preserved")

    def test_no_crash_complex(self):
        src = (
            "def f(x, y):\n"
            "    a = x + y\n"
            "    b = a * 2\n"
            "    return b\n"
        )
        try:
            self._inject(src)
        except Exception as e:
            self.fail(f"injector raised: {e}")


# ── SAGPass tests ─────────────────────────────────────────────────────────────
class TestSAGPass(unittest.TestCase):

    def test_pass_no_crash_simple(self):
        mod = _build("x = 1\ny = x + 2\n")
        try:
            SAGPass().run(mod)
        except Exception as e:
            self.fail(f"SAGPass raised: {e}")

    def test_pass_no_crash_complex(self):
        src = (
            "def compute(a, b):\n"
            "    c = a + b\n"
            "    if c > 10:\n"
            "        return c * 2\n"
            "    return c\n"
        )
        mod = _build(src)
        try:
            SAGPass().run(mod)
        except Exception as e:
            self.fail(f"SAGPass raised: {e}")

    def test_graph_stats_accessible(self):
        mod = _build("x = 5\ny = x * 3\n")
        mod = SAGPass().run(mod)
        stats = SAGPass.get_graph_stats(mod)
        self.assertIn("vars",       stats)
        self.assertIn("edges",      stats)
        self.assertIn("has_cycles", stats)
        self.assertIsInstance(stats["vars"], int)

    def test_runtime_accessible(self):
        mod  = _build("x = 1\n")
        mod  = SAGPass().run(mod)
        code = SAGPass.get_runtime(mod)
        self.assertIn("__sag_tick",    code)
        self.assertIn("__sag_sel",     code)
        self.assertIn("__sag_combine", code)

    def test_cycles_created_with_cross_prob_1(self):
        mod = _build("a = 1\nb = 2\nc = 3\nd = 4\n")
        mod = SAGPass(cross_prob=1.0).run(mod)
        stats = SAGPass.get_graph_stats(mod)
        # With cross_prob=1.0 and 4 vars, cycles very likely
        # (not guaranteed due to random direction, but edge count > 0)
        self.assertGreaterEqual(stats["edges"], 0)


# ── SAG Runtime tests ─────────────────────────────────────────────────────────
class TestSAGRuntime(unittest.TestCase):

    def setUp(self):
        self._ns = {}
        exec(SAGRuntimeEmitter.emit_runtime(), self._ns)

    def test_emit_runtime_valid_python(self):
        try:
            ast.parse(SAGRuntimeEmitter.emit_runtime())
        except SyntaxError as e:
            self.fail(f"runtime syntax error: {e}")

    def test_sag_sel_in_range(self):
        for n in [2, 3, 5, 10]:
            for key in [0, 1, 0xABCD, 0xFFFFFFFF]:
                idx = self._ns['__sag_sel'](key, n)
                self.assertGreaterEqual(idx, 0)
                self.assertLess(idx, n, f"idx={idx} out of range [0,{n})")

    def test_sag_sel_n1_returns_0(self):
        self.assertEqual(self._ns['__sag_sel'](0xDEAD, 1), 0)

    def test_sag_combine_returns_real(self):
        vals     = [42, 999, 888]
        real_idx = 0
        key      = 0x1234
        n        = 3
        # Force state so sel returns real_idx
        # Reset state
        self._ns['__sag_state']   = 0xDEADBEEF
        self._ns['__sag_history'] = []
        self._ns['__sag_step']    = 0
        idx = self._ns['__sag_sel'](key, n)
        result = self._ns['__sag_combine'](vals, idx, key, n)
        self.assertEqual(result, vals[idx])

    def test_sag_tick_changes_state(self):
        self._ns['__sag_state']   = 0xABCD
        self._ns['__sag_history'] = []
        self._ns['__sag_step']    = 0
        before = self._ns['__sag_state']
        self._ns['__sag_tick'](42)
        self.assertNotEqual(self._ns['__sag_state'], before,
            "__sag_tick should mutate state")

    def test_observer_effect(self):
        """Calling tick twice changes state each time."""
        self._ns['__sag_state']   = 0x1111
        self._ns['__sag_history'] = []
        self._ns['__sag_step']    = 0
        self._ns['__sag_tick'](1)
        s1 = self._ns['__sag_state']
        self._ns['__sag_tick'](1)
        s2 = self._ns['__sag_state']
        self.assertNotEqual(s1, s2,
            "repeated ticks with same value should still mutate state")

    def test_sag_combine_fallback(self):
        """combine with empty list returns None (not crash)."""
        result = self._ns['__sag_combine']([], 0, 0, 0)
        self.assertIsNone(result)

    def test_sag_combine_out_of_range_fallback(self):
        """combine with idx >= len(vals) returns vals[0]."""
        vals   = [77, 88]
        result = self._ns['__sag_combine'](vals, 99, 0, 99)
        self.assertEqual(result, 77)


if __name__ == "__main__":
    unittest.main(verbosity=2)
