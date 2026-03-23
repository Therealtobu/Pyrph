"""
Integration test: chạy full pipeline với cả 3 module mới.
Test các trường hợp thực tế.
"""
import sys; sys.path.insert(0, '.')
import ast, unittest

from ..ir.builder              import IRBuilder
from ..ir.cfg                  import CFGBuilder
from ..ir.dependency           import DependencyAnalyzer
from ..ir_obf.semantic_fingerprint import SemanticFingerprintPass
from ..ir_obf.substitution     import InstructionSubstitutor
from ..ir_obf.shuffler         import InstructionShuffler
from ..ir_obf.rewriter         import ControlFlowRewriter
from ..ir_obf.encryptor        import BlockEncryptor
from ..ir_obf.mutating_const_pool  import MutatingConstPool
from ..vm.resolver_v2          import OpcodeResolverV2
from ..vm.interleaver          import Interleaver
from ..vm.codegen              import VMCodeGen

exec(MutatingConstPool.emit_runtime())   # defines _MCP  # noqa


def _pipeline(source: str) -> str:
    tree      = ast.parse(source)
    mod       = IRBuilder().build(tree)
    CFGBuilder().build(mod)
    DependencyAnalyzer().analyze(mod)
    # Tier-1 passes
    mod = SemanticFingerprintPass().run(mod)
    mod = InstructionSubstitutor().run(mod)
    mod = InstructionShuffler().run(mod)
    mod = ControlFlowRewriter().run(mod)
    mod = BlockEncryptor().run(mod)
    bc  = Interleaver().interleave(mod)
    return VMCodeGen().generate(bc, mod)


class TestPipelineDoesNotCrash(unittest.TestCase):

    def test_simple_assignment(self):
        out = _pipeline("x = 42\n")
        self.assertIn("_VM3", out)
        self.assertIn("__BC", out)

    def test_arithmetic(self):
        out = _pipeline("x = 1\ny = x + 2\nz = y * 3\n")
        self.assertIsInstance(out, str)
        self.assertGreater(len(out), 500)

    def test_function_def(self):
        out = _pipeline("def add(a, b):\n    return a + b\n")
        self.assertIn("_VM3", out)

    def test_if_else(self):
        out = _pipeline("x = 10\nif x > 5:\n    y = 1\nelse:\n    y = 0\n")
        self.assertIsInstance(out, str)

    def test_for_loop(self):
        out = _pipeline("s = 0\nfor i in range(5):\n    s = s + i\n")
        self.assertIsInstance(out, str)

    def test_string_present_in_tables(self):
        out = _pipeline('msg = "hello"\n')
        self.assertIn("__TABLES", out)

    def test_output_has_bootstrap(self):
        out = _pipeline("x = 1\n")
        self.assertIn("__K1", out)
        self.assertIn("__K2", out)
        self.assertIn("__vm.run", out)

    def test_multiple_functions(self):
        src = "def f(x): return x+1\ndef g(x): return x*2\nresult = f(g(3))\n"
        out = _pipeline(src)
        self.assertIsInstance(out, str)

    def test_nested_ops(self):
        src = "a=1\nb=2\nc=3\nresult = (a+b)*c - (b-a)\n"
        out = _pipeline(src)
        self.assertGreater(len(out), 1000)


class TestMCPInPipeline(unittest.TestCase):
    """MutatingConstPool roundtrips correctly for values seen in IR."""

    def test_typical_const_table(self):
        import random
        consts = {i: random.randint(-1000, 1000) for i in range(30)}
        mcp    = MutatingConstPool(seed=0x12345678)
        enc, masks, seed = mcp.encode_table(consts)
        pool   = _MCP(enc, masks, seed)  # noqa
        for idx, expected in consts.items():
            self.assertEqual(pool.get(idx), expected, f"idx={idx}")


class TestResolverV2InPipeline(unittest.TestCase):
    """OpcodeResolverV2 sequential encode→decode for a realistic op sequence."""

    def test_realistic_opcode_sequence(self):
        from ..vm.opcodes import VM1Op
        key  = 0xFEED_FACE
        # Simulate encoding at compile time
        enc_r = OpcodeResolverV2(key=key)
        ops   = [VM1Op.RLOAD_CONST, VM1Op.RLOAD_VAR, VM1Op.RADD,
                 VM1Op.RSTORE_VAR, VM1Op.JMP, VM1Op.RET]
        encoded = []
        for op in ops:
            enc = enc_r.encode(int(op))
            encoded.append(enc)
            enc_r.resolve(enc)   # advance

        # Simulate decoding at runtime
        dec_r   = OpcodeResolverV2(key=key)
        decoded = [dec_r.resolve(e) & 0xFF for e in encoded]
        expected = [int(op) & 0xFF for op in ops]
        self.assertEqual(decoded, expected)

    def test_data_flow_feed_does_not_break_resolve(self):
        r = OpcodeResolverV2(key=0xAAAA)
        for val in [42, -1, 0, 2**16, "hello"]:
            r.feed_data(val)   # must not raise
        # Still resolves something
        result = r.resolve(0x1234)
        self.assertIsInstance(result, int)


if __name__ == "__main__":
    unittest.main(verbosity=2)
