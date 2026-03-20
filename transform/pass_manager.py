"""TransformPassManager – runs AST obfuscation passes in order."""
import ast
from .cff                    import ControlFlowFlattener
from .mba                    import MBAExpander
from .string_lifting         import StringLifter
from .constant_virtualization import ConstantVirtualizer
from .function_splitting     import FunctionSplitter
from .opaque_predicates      import OpaquePredicates


class TransformPassManager:
    _PASSES = [
        StringLifter,          # lift strings first (simpler targets)
        ConstantVirtualizer,
        OpaquePredicates,
        MBAExpander,
        ControlFlowFlattener,
        FunctionSplitter,      # last – may move functions around
    ]

    def __init__(self):
        self._passes = [P() for P in self._PASSES]

    def run(self, tree: ast.AST) -> ast.AST:
        for p in self._passes:
            tree = p.transform(tree)
            ast.fix_missing_locations(tree)
        return tree
