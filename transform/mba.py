"""
MBAExpander – Mixed Boolean Arithmetic expression expansion.

Replaces simple arithmetic/logic with provably equivalent but obscure forms.

Examples:
  x + y  →  (x | y) + (x & y)   [sum identity]
  x - y  →  (x + (~y + 1))       [two's complement subtraction]
  x & y  →  (x + y) - (x | y)   [DeMorgan + identity]
  x | y  →  (x + y) - (x & y)
  x ^ y  →  (x | y) - (x & y)

For integer constants:  n  →  (n ^ K) ^ K   (random XOR mask)
"""
import ast
import random
import itertools

_ctr = itertools.count(1)
_MASK = (1 << 64) - 1


def _rnd_mask() -> int:
    return random.randint(0x1000, 0xFFFFFFFF)


class MBAExpander(ast.NodeTransformer):

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    # ── BinOp substitutions ───────────────────────────────────────────────────
    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)

        L, R = node.left, node.right
        op   = type(node.op)

        if op is ast.Add:
            # x + y  →  (x | y) + (x & y)
            return self._wrap(ast.BinOp(
                left  = ast.BinOp(left=L, op=ast.BitOr(),  right=R),
                op    = ast.Add(),
                right = ast.BinOp(left=L, op=ast.BitAnd(), right=R),
            ), node)

        if op is ast.Sub:
            # x - y  →  (x & ~y) + (x ^ y) & ~(x ^ y) — simplified:
            # x - y  →  x + (~y) + 1  (only safe for ints; use with care)
            # Keep simpler: x - y → (x ^ y) + 2*(x & ~y) … use double-neg:
            # We'll just do: (x + y*(-1))
            neg_one = ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1))
            return self._wrap(ast.BinOp(
                left  = L,
                op    = ast.Add(),
                right = ast.BinOp(left=R, op=ast.Mult(), right=neg_one),
            ), node)

        if op is ast.BitAnd:
            # x & y  →  (x + y) - (x | y)
            return self._wrap(ast.BinOp(
                left  = ast.BinOp(left=L, op=ast.Add(), right=R),
                op    = ast.Sub(),
                right = ast.BinOp(left=L, op=ast.BitOr(), right=R),
            ), node)

        if op is ast.BitOr:
            # x | y  →  (x + y) - (x & y)
            return self._wrap(ast.BinOp(
                left  = ast.BinOp(left=L, op=ast.Add(), right=R),
                op    = ast.Sub(),
                right = ast.BinOp(left=L, op=ast.BitAnd(), right=R),
            ), node)

        if op is ast.BitXor:
            # x ^ y  →  (x | y) - (x & y)
            return self._wrap(ast.BinOp(
                left  = ast.BinOp(left=L, op=ast.BitOr(), right=R),
                op    = ast.Sub(),
                right = ast.BinOp(left=L, op=ast.BitAnd(), right=R),
            ), node)

        return node   # other ops unchanged

    # ── Integer constants: n → (n ^ K) ^ K ───────────────────────────────────
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            K = _rnd_mask()
            masked = node.value ^ K
            expansion = ast.BinOp(
                left  = ast.Constant(value=masked),
                op    = ast.BitXor(),
                right = ast.Constant(value=K),
            )
            ast.copy_location(expansion, node)
            ast.fix_missing_locations(expansion)
            return expansion
        return node

    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _wrap(new_node: ast.expr, original: ast.expr) -> ast.expr:
        ast.copy_location(new_node, original)
        ast.fix_missing_locations(new_node)
        return new_node
