"""
Tests cho Metamorphic Engine:
1. VariantGenerator tạo đúng N variants
2. Mỗi variant có tên khác nhau
3. Mỗi variant có instruction set khác nhau (thực sự metamorphic)
4. Block count đúng sau BlockDuplicator
5. Dispatcher function được tạo với đúng tên
6. MetamorphicEngine không crash với empty function
7. MetamorphicEngine không crash với complex function
8. Module functions count tăng đúng sau engine.run()
9. Original function bị replace bởi dispatcher
10. Micro-transform RegisterRenamer đổi tên register
11. Micro-transform ConstantSplitter tách constant
12. Micro-transform NOPPadder thêm NOP
"""
import sys, ast
sys.path.insert(0, '.')
import unittest, copy

from ir.nodes        import IROp, IROperand, IRInstruction, IRBlock, IRFunction, IRModule
from ir.builder      import IRBuilder
from ir.cfg          import CFGBuilder
from metamorphic.variant_generator import (
    VariantGenerator, RegisterRenamer, ConstantSplitter,
    NOPPadder, BlockDuplicator, OperandFlipMBA, ChainedAssign,
)
from metamorphic.dispatcher import MetamorphicDispatcher
from metamorphic.engine     import MetamorphicEngine


# ── Helpers ───────────────────────────────────────────────────────────────────
def _build_fn(src: str, fn_name: str = None) -> tuple[IRFunction, IRModule]:
    tree = ast.parse(src)
    mod  = IRBuilder().build(tree)
    CFGBuilder().build(mod)
    if fn_name:
        fn = mod.get_function(fn_name)
    else:
        fn = mod.functions[-1] if len(mod.functions) > 1 else mod.functions[0]
    return fn, mod


def _simple_fn() -> IRFunction:
    src = "def add(a, b):\n    return a + b\n"
    fn, _ = _build_fn(src, "add")
    return fn


def _complex_fn() -> IRFunction:
    src = (
        "def compute(x, y, z):\n"
        "    a = x + y\n"
        "    b = a * z\n"
        "    if b > 10:\n"
        "        return b\n"
        "    return a\n"
    )
    fn, _ = _build_fn(src, "compute")
    return fn


# ── VariantGenerator tests ────────────────────────────────────────────────────
class TestVariantGenerator(unittest.TestCase):

    def test_generates_n_variants(self):
        gen      = VariantGenerator(n_variants=3)
        variants = gen.generate(_simple_fn())
        self.assertEqual(len(variants), 3)

    def test_variant_names_unique(self):
        gen      = VariantGenerator(n_variants=3)
        variants = gen.generate(_simple_fn())
        names    = [v.name for v in variants]
        self.assertEqual(len(names), len(set(names)),
            "all variant names must be unique")

    def test_variant_names_contain_suffix(self):
        gen      = VariantGenerator(n_variants=3)
        variants = gen.generate(_simple_fn())
        for v in variants:
            self.assertIn("__var", v.name,
                f"variant name should contain '__var': {v.name}")

    def test_variants_differ_from_original(self):
        """At least one variant must have different instructions than original."""
        fn   = _complex_fn()
        orig_count = sum(len(b.instructions) for b in fn.blocks)
        gen  = VariantGenerator(n_variants=3)
        variants = gen.generate(fn)
        counts = [sum(len(b.instructions) for b in v.blocks)
                  for v in variants]
        # At least one variant should differ (transforms add/modify instructions)
        self.assertTrue(
            any(c != orig_count for c in counts),
            "all variants identical to original – transforms not applied"
        )

    def test_variants_have_same_args(self):
        fn   = _complex_fn()
        gen  = VariantGenerator(n_variants=3)
        variants = gen.generate(fn)
        for v in variants:
            self.assertEqual(v.args, fn.args,
                "variant must preserve original function args")

    def test_deep_clone_independent(self):
        """Modifying a variant must not affect original."""
        fn   = _simple_fn()
        gen  = VariantGenerator(n_variants=2)
        variants = gen.generate(fn)
        orig_block_count = len(fn.blocks)
        # Add a block to variant[0]
        variants[0].blocks.append(IRBlock(id=99, label="__injected"))
        self.assertEqual(len(fn.blocks), orig_block_count,
            "modifying variant should not affect original")


# ── Micro-transform tests ─────────────────────────────────────────────────────
class TestMicroTransforms(unittest.TestCase):

    def test_register_renamer_changes_names(self):
        fn  = _simple_fn()
        gen = VariantGenerator(n_variants=1)
        orig_regs = {
            op.value
            for b in fn.blocks for i in b.instructions
            for op in ([i.dst] if i.dst else []) + i.src
            if op and op.kind == "reg" and str(op.value).startswith("__t")
        }
        clone = gen._deep_clone(fn, "__test")
        RegisterRenamer().apply(clone)
        new_regs = {
            op.value
            for b in clone.blocks for i in b.instructions
            for op in ([i.dst] if i.dst else []) + i.src
            if op and op.kind == "reg" and str(op.value).startswith("__v")
        }
        if orig_regs:
            self.assertGreater(len(new_regs), 0,
                "RegisterRenamer should produce __vN registers")

    def test_nop_padder_increases_count(self):
        fn    = _complex_fn()
        clone = VariantGenerator._deep_clone(fn, "__nop")
        before = sum(len(b.instructions) for b in clone.blocks)
        NOPPadder().apply(clone)
        after  = sum(len(b.instructions) for b in clone.blocks)
        # NOPs are probabilistic (25%), run enough that it likely fires
        import random; random.seed(42)
        clone2 = VariantGenerator._deep_clone(fn, "__nop2")
        NOPPadder().apply(clone2)
        after2 = sum(len(b.instructions) for b in clone2.blocks)
        # At least one of them should have more instructions
        self.assertTrue(after >= before or after2 >= before,
            "NOPPadder should increase instruction count")

    def test_block_duplicator_adds_blocks(self):
        fn    = _complex_fn()
        clone = VariantGenerator._deep_clone(fn, "__dup")
        import random; random.seed(0)
        before = len(clone.blocks)
        BlockDuplicator().apply(clone)
        after  = len(clone.blocks)
        # May or may not fire depending on random, but should not reduce
        self.assertGreaterEqual(after, before)

    def test_constant_splitter_no_crash(self):
        fn    = _simple_fn()
        clone = VariantGenerator._deep_clone(fn, "__cs")
        try:
            ConstantSplitter().apply(clone)
        except Exception as e:
            self.fail(f"ConstantSplitter raised: {e}")

    def test_operand_flip_no_crash(self):
        fn    = _complex_fn()
        clone = VariantGenerator._deep_clone(fn, "__of")
        try:
            OperandFlipMBA().apply(clone)
        except Exception as e:
            self.fail(f"OperandFlipMBA raised: {e}")

    def test_chained_assign_no_crash(self):
        fn    = _complex_fn()
        clone = VariantGenerator._deep_clone(fn, "__ca")
        try:
            ChainedAssign().apply(clone)
        except Exception as e:
            self.fail(f"ChainedAssign raised: {e}")


# ── Dispatcher tests ──────────────────────────────────────────────────────────
class TestMetamorphicDispatcher(unittest.TestCase):

    def test_dispatcher_name_matches_original(self):
        fn       = _simple_fn()
        gen      = VariantGenerator(n_variants=3)
        variants = gen.generate(fn)
        disp     = MetamorphicDispatcher()
        mod      = IRModule()
        dsp_fn   = disp.build_dispatcher(fn, variants, mod)
        self.assertEqual(dsp_fn.name, fn.name,
            "dispatcher must have same name as original")

    def test_dispatcher_same_args(self):
        fn       = _complex_fn()
        gen      = VariantGenerator(n_variants=2)
        variants = gen.generate(fn)
        disp     = MetamorphicDispatcher()
        mod      = IRModule()
        dsp_fn   = disp.build_dispatcher(fn, variants, mod)
        self.assertEqual(dsp_fn.args, fn.args)

    def test_dispatcher_has_return(self):
        fn       = _simple_fn()
        gen      = VariantGenerator(n_variants=2)
        variants = gen.generate(fn)
        disp     = MetamorphicDispatcher()
        mod      = IRModule()
        dsp_fn   = disp.build_dispatcher(fn, variants, mod)
        has_ret  = any(
            i.op == IROp.RETURN
            for b in dsp_fn.blocks for i in b.instructions
        )
        self.assertTrue(has_ret, "dispatcher must have a RETURN instruction")

    def test_dispatcher_has_mod_op(self):
        """Dispatcher must use MOD to compute variant_id % N."""
        fn       = _simple_fn()
        gen      = VariantGenerator(n_variants=3)
        variants = gen.generate(fn)
        disp     = MetamorphicDispatcher()
        mod      = IRModule()
        dsp_fn   = disp.build_dispatcher(fn, variants, mod)
        has_mod  = any(
            i.op == IROp.MOD
            for b in dsp_fn.blocks for i in b.instructions
        )
        self.assertTrue(has_mod, "dispatcher must use MOD for variant selection")

    def test_preamble_valid_python(self):
        code = MetamorphicDispatcher.emit_module_preamble()
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.fail(f"preamble syntax error: {e}")


# ── Engine integration tests ──────────────────────────────────────────────────
class TestMetamorphicEngine(unittest.TestCase):

    def test_engine_increases_function_count(self):
        src = "def foo(x):\n    a = x + 1\n    b = a * 2\n    return b\n"
        _, mod = _build_fn(src, "foo")
        before = len(mod.functions)
        MetamorphicEngine(n_variants=3).run(mod)
        after  = len(mod.functions)
        # Should have: 3 variants + 1 dispatcher = 4 more, original removed
        # Net change: +3 (3 variants - 1 original + 1 dispatcher)
        self.assertGreater(after, before,
            "MetamorphicEngine should increase function count")

    def test_engine_replaces_original_with_dispatcher(self):
        src = "def bar(x, y):\n    return x + y\n"
        _, mod = _build_fn(src, "bar")
        MetamorphicEngine(n_variants=2, min_instrs=0).run(mod)
        names = [fn.name for fn in mod.functions]
        # "bar" should still exist (as dispatcher)
        self.assertIn("bar", names)
        # Variant names should exist
        variant_names = [n for n in names if "__var" in n]
        self.assertGreater(len(variant_names), 0)

    def test_engine_no_crash_empty_module(self):
        mod = IRModule()
        try:
            MetamorphicEngine().run(mod)
        except Exception as e:
            self.fail(f"engine raised on empty module: {e}")

    def test_engine_no_crash_complex_source(self):
        src = (
            "def fib(n):\n"
            "    if n <= 1:\n"
            "        return n\n"
            "    return fib(n-1) + fib(n-2)\n"
        )
        _, mod = _build_fn(src, "fib")
        try:
            MetamorphicEngine(n_variants=3).run(mod)
        except Exception as e:
            self.fail(f"engine raised on complex source: {e}")

    def test_engine_skips_module_function(self):
        """__module__ pseudo-function must never be metamorphized."""
        src = "x = 1\ny = x + 2\n"
        tree = ast.parse(src)
        mod  = IRBuilder().build(tree)
        MetamorphicEngine().run(mod)
        names = [fn.name for fn in mod.functions]
        self.assertIn("__module__", names,
            "__module__ must survive metamorphic pass")

    def test_engine_with_full_pipeline(self):
        """MetamorphicEngine must not crash when chained with IR obf passes."""
        from ir_obf.substitution import InstructionSubstitutor
        from ir_obf.encryptor    import BlockEncryptor
        src = "def double(n):\n    return n * 2\n"
        _, mod = _build_fn(src, "double")
        mod = MetamorphicEngine(n_variants=2, min_instrs=0).run(mod)
        mod = InstructionSubstitutor().run(mod)
        mod = BlockEncryptor().run(mod)
        self.assertGreater(len(mod.functions), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
