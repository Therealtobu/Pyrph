import os, sys
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path: sys.path.insert(0, _DIR)

"""
ObfuscationPipeline – V3 Final with SAG + Metamorphic Engine.

Phase order:
  1. parse
  2. normalize
  3. transform
  4. IR build
  5. IR obf     (import-obf, semantic-fp, substitution, shuffle, rewrite, encrypt)
  6. SAG ★ NEW  (semantic alias graph – variable origin obfuscation)
  7. metamorphic (variant cloning + dispatch)
  8. VM compile
"""
import ast
import config

from normalize.pass_manager         import NormalizePassManager
from transform.pass_manager         import TransformPassManager
from ir.builder                     import IRBuilder
from ir.cfg                         import CFGBuilder
from ir.dependency                  import DependencyAnalyzer
from vm.import_obf                  import ImportObfuscator
from ir_obf.semantic_fingerprint    import SemanticFingerprintPass
from ir_obf.substitution            import InstructionSubstitutor
from ir_obf.shuffler                import InstructionShuffler
from ir_obf.rewriter                import ControlFlowRewriter
from ir_obf.encryptor               import BlockEncryptor
from sag.sag_pass                   import SAGPass
from metamorphic.engine             import MetamorphicEngine
from vm.interleaver                 import Interleaver
from vm.codegen                     import VMCodeGen


class ObfuscationPipeline:
    def __init__(self):
        self._norm  = NormalizePassManager()
        self._trans = TransformPassManager()
        self._impo  = ImportObfuscator()
        self._sfp   = SemanticFingerprintPass()
        self._subst = InstructionSubstitutor()
        self._shuf  = InstructionShuffler()
        self._rw    = ControlFlowRewriter()
        self._enc   = BlockEncryptor()
        self._sag   = SAGPass()
        self._meta  = MetamorphicEngine(n_variants=3)
        self._ilv   = Interleaver()
        self._cgen  = VMCodeGen()

    def run(self, source: str) -> str:
        tree = ast.parse(source)

        if config.ENABLE_NORMALIZE:
            tree = self._norm.run(tree)

        if config.ENABLE_TRANSFORM:
            tree = self._trans.run(tree)

        ir_module = IRBuilder().build(tree)
        CFGBuilder().build(ir_module)
        DependencyAnalyzer().analyze(ir_module)

        if config.ENABLE_IR_OBF:
            ir_module = self._impo.run(ir_module)
            ir_module = self._sfp.run(ir_module)
            ir_module = self._subst.run(ir_module)
            ir_module = self._shuf.run(ir_module)
            ir_module = self._rw.run(ir_module)
            ir_module = self._enc.run(ir_module)
            ir_module = self._sag.run(ir_module)      # ★ SAG
            ir_module = self._meta.run(ir_module)

        if config.ENABLE_VM:
            vm3_bc = self._ilv.interleave(ir_module)
            output = self._cgen.generate(vm3_bc, ir_module)
        else:
            output = ast.unparse(tree)

        return output
