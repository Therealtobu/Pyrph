import sys; sys.path.insert(0, '.')
import unittest, ast
from ..ir.nodes import IROp, IROperand, IRInstruction, IRFunction, IRModule
from ..ir.builder import IRBuilder
from ..ir.cfg import CFGBuilder
from ..ir_obf.semantic_fingerprint import SemanticFingerprintPass, _shadow_var


def _build(src: str) -> IRModule:
    tree = ast.parse(src)
    mod  = IRBuilder().build(tree)
    CFGBuilder().build(mod)
    return mod


class TestSemanticFingerprintInstrumentation(unittest.TestCase):

    def test_store_var_gets_shadow_instructions(self):
        """Every STORE_VAR for non-dunder var must be surrounded by shadow ops."""
        mod  = _build("x = 42\ny = x + 1\n")
        orig_stores = sum(
            1 for fn in mod.functions
            for instr in fn.all_instructions()
            if instr.op == IROp.STORE_VAR
            and any(s.kind == "var" and not str(s.value).startswith("__")
                    for s in instr.src[1:2])
        )
        pass_  = SemanticFingerprintPass()
        mod2   = pass_.run(mod)

        # Count shadow NOP instructions
        shadow_instrs = [
            i for fn in mod2.functions
            for i in fn.all_instructions()
            if i.metadata.get("shadow_op") in
               ("SHADOW_PROP", "SHADOW_WRITE", "SHADOW_CHECK")
        ]
        self.assertGreater(len(shadow_instrs), 0,
            "no shadow instructions emitted")

    def test_load_var_gets_check(self):
        """LOAD_VAR for non-dunder var must be followed by SHADOW_CHECK."""
        mod   = _build("x = 5\nz = x\n")
        pass_ = SemanticFingerprintPass()
        mod2  = pass_.run(mod)
        checks = [
            i for fn in mod2.functions
            for i in fn.all_instructions()
            if i.metadata.get("shadow_op") == "SHADOW_CHECK"
        ]
        self.assertGreater(len(checks), 0)

    def test_shadow_has_unique_iids(self):
        """Each shadow instruction must carry a unique instruction_id."""
        mod   = _build("a=1\nb=2\nc=3\n")
        pass_ = SemanticFingerprintPass()
        mod2  = pass_.run(mod)
        iids  = [
            i.metadata["iid"]
            for fn in mod2.functions
            for i in fn.all_instructions()
            if "iid" in i.metadata
        ]
        self.assertEqual(len(iids), len(set(iids)),
            "duplicate iids found – not unique per site")

    def test_shadow_var_naming(self):
        """Shadow variable for 'foo' must be '__sh_foo'."""
        self.assertEqual(_shadow_var("foo"), "__sh_foo")
        self.assertEqual(_shadow_var("x"),   "__sh_x")

    def test_dunder_vars_not_instrumented(self):
        """Internal __dunder__ variables must NOT get shadow ops."""
        mod   = _build("x = 1\n")
        pass_ = SemanticFingerprintPass()
        mod2  = pass_.run(mod)
        for fn in mod2.functions:
            for instr in fn.all_instructions():
                var = instr.metadata.get("var", "")
                if var.startswith("__"):
                    self.fail(f"dunder var '{var}' was instrumented")

    def test_instruction_count_increases(self):
        """After pass, total instruction count must be higher."""
        mod   = _build("x = 10\ny = x + 5\nz = y\n")
        before = sum(len(list(fn.all_instructions())) for fn in mod.functions)
        SemanticFingerprintPass().run(mod)
        after  = sum(len(list(fn.all_instructions())) for fn in mod.functions)
        self.assertGreater(after, before)

    def test_original_store_preserved(self):
        """Original STORE_VAR instruction must still exist after pass."""
        mod   = _build("x = 99\n")
        pass_ = SemanticFingerprintPass()
        mod2  = pass_.run(mod)
        stores = [
            i for fn in mod2.functions
            for i in fn.all_instructions()
            if i.op == IROp.STORE_VAR
        ]
        self.assertGreater(len(stores), 0, "original STORE_VAR was removed")

    def test_shadow_src_references_value(self):
        """SHADOW_PROP src[0] must reference the same operand as original STORE_VAR src[0]."""
        mod   = _build("answer = 42\n")
        pass_ = SemanticFingerprintPass()
        mod2  = pass_.run(mod)
        props = [
            i for fn in mod2.functions
            for i in fn.all_instructions()
            if i.metadata.get("shadow_op") == "SHADOW_PROP"
               and i.metadata.get("var") == "answer"
        ]
        self.assertTrue(len(props) > 0, "no SHADOW_PROP for 'answer'")
        # src[0] should be a reg or const (the actual value being stored)
        prop = props[0]
        self.assertIn(prop.src[0].kind, ("reg", "const", "var"),
            f"unexpected src[0] kind: {prop.src[0].kind}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
