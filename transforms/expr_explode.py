"""
transforms/expr_explode.py
===========================
ExprExplodePass — expression explosion via deep substitution.

Takes simple integer expressions and replaces them with deeply nested
equivalent expressions that are semantically identical but visually
and structurally overwhelming to analyse.

Techniques:
  1. Split constants into chains of operations:
       42 → ((((40+1)+1) & 0xFF) ^ 0) | 0
  2. Wrap boolean expressions in redundant logic:
       x > 0 → (not (not (x > 0))) and (x >= 0 or x > 0)
  3. Expand comparisons into redundant compound forms:
       a == b → (a == b) and not (a != b)
  4. Replace numeric ops with function-call chains:
       abs(x) → (lambda _v: _v if _v >= 0 else -_v)(x)

Depth is limited to avoid code size explosion.
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _n(v):   return ast.Constant(value=v)
def _bi(l,op,r): return ast.BinOp(left=l, op=op(), right=r)
def _cmp(l,op,r): return ast.Compare(left=l, ops=[op()], comparators=[r])
def _not(x):  return ast.UnaryOp(op=ast.Not(), operand=x)
def _and(a,b): return ast.BoolOp(op=ast.And(), values=[a,b])
def _or(a,b):  return ast.BoolOp(op=ast.Or(),  values=[a,b])


# ── Integer constant explosion ────────────────────────────────────────────

def _explode_const(n: int, depth: int) -> ast.expr:
    """Turn integer n into a deeply nested expression."""
    if depth <= 0 or abs(n) > 0xFFFF:
        return _n(n)
    style = random.randint(0, 3)
    if style == 0:
        # (n ^ K) ^ K
        k = random.randint(1, 0xFF)
        inner = _bi(_n(n), ast.BitXor, _n(k))
        return _bi(inner, ast.BitXor, _n(k))
    elif style == 1:
        # (n + K) - K
        k = random.randint(1, 0xFF)
        inner = _bi(_n(n), ast.Add, _n(k))
        return _bi(inner, ast.Sub, _n(k))
    elif style == 2:
        # ((n << s) >> s)
        s = random.randint(1, 3)
        if n > 0:
            return _bi(_bi(_n(n), ast.LShift, _n(s)), ast.RShift, _n(s))
        return _n(n)
    else:
        # (n | 0) & (0xFFFFFFFF if n >= 0 else n)
        mask = _bi(_n(n), ast.BitOr, _n(0))
        return _bi(mask, ast.BitAnd, _n(0xFFFF))


# ── Boolean explosion ─────────────────────────────────────────────────────

def _explode_bool(expr: ast.expr, depth: int) -> ast.expr:
    """Wrap boolean expr in redundant double-negation."""
    if depth <= 0:
        return expr
    style = random.randint(0, 1)
    if style == 0:
        # not (not expr)
        return _not(_not(expr))
    else:
        # (expr) and (expr or expr) — tautology
        return _and(expr, _or(expr, expr))


# ── Comparison explosion ──────────────────────────────────────────────────

def _explode_eq(l: ast.expr, r: ast.expr) -> ast.expr:
    """a == b → (a == b) and not (a != b)"""
    eq  = _cmp(l, ast.Eq,    r)
    neq = _cmp(l, ast.NotEq, r)
    return _and(eq, _not(neq))


def _explode_ne(l: ast.expr, r: ast.expr) -> ast.expr:
    """a != b → not (a == b)"""
    return _not(_cmp(l, ast.Eq, r))


# ── Transformer ───────────────────────────────────────────────────────────

class _ExplodeTransformer(ast.NodeTransformer):
    def __init__(self, density: float, max_depth: int):
        self.density   = density
        self.max_depth = max_depth
        self.count     = 0
        self._depth    = 0

    def _should(self) -> bool:
        return self._depth < self.max_depth and random.random() < self.density

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if (isinstance(node.value, int) and
                not isinstance(node.value, bool) and
                0 < abs(node.value) <= 0xFFFF and
                self._should()):
            self._depth += 1
            new = _explode_const(node.value, self.max_depth - self._depth)
            self._depth -= 1
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            self.count += 1
            return new
        return node

    def visit_Compare(self, node: ast.Compare) -> ast.expr:
        self.generic_visit(node)
        if len(node.ops) != 1 or not self._should():
            return node
        op = type(node.ops[0])
        l  = node.left
        r  = node.comparators[0]
        new = None
        if op is ast.Eq:
            new = _explode_eq(l, r)
        elif op is ast.NotEq:
            new = _explode_ne(l, r)
        if new:
            self.count += 1
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            return new
        return node


class ExprExplodePass(ObfPass):
    name        = "expr_explode"
    phase       = 2
    description = "Deep expression explosion: constants → nested ops, comparisons → tautologies"

    def run(self, code: str) -> ObfResult:
        if not self.enabled:
            return self._skip(code)
        try:
            density   = self.opts.get("density",   0.40)
            max_depth = self.opts.get("max_depth",  3)
            tree      = ast.parse(code)
            t         = _ExplodeTransformer(density, max_depth)
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(
                ast.unparse(tree),
                message=f"exploded {t.count} expression(s)",
                count=t.count,
            )
        except Exception as exc:
            return self._err(code, exc)
