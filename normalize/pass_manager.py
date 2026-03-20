"""
NormalizePassManager
Runs all normalization passes in a fixed order.
Each pass is an ast.NodeTransformer with a .transform(tree) method.
"""
import ast
from .lambda_inliner         import LambdaInliner
from .comprehension_expander import ComprehensionExpander
from .ternary_expander       import TernaryExpander
from .sugar_remover          import SugarRemover


class NormalizePassManager:
    _PASSES = [
        LambdaInliner,
        ComprehensionExpander,
        TernaryExpander,
        SugarRemover,
    ]

    def __init__(self):
        self._passes = [P() for P in self._PASSES]

    def run(self, tree: ast.AST) -> ast.AST:
        for p in self._passes:
            tree = p.transform(tree)
            ast.fix_missing_locations(tree)
        return tree
