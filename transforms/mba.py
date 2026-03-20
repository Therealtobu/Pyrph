"""
transforms/mba.py
==================
MBAPass — Mixed Boolean-Arithmetic transforms at AST level.

Replaces integer arithmetic and bitwise ops with semantically equivalent
but structurally complex MBA expressions that defeat pattern-based
decompilers and symbolic analysis engines.

MBA identities used (all verified for Python arbitrary-precision ints):
  a + b  → (a ^ b) + ((a & b) << 1)
          OR (a | b) + (a & b)
  a - b  → (a ^ b) - ((~a & b) << 1)
  a ^ b  → (a + b) - ((a & b) << 1)
  a & b  → ((a + b) - (a ^ b)) >> 1
  a | b  → (a ^ b) + (a & b)
  ~a     → (-a) - 1

Depth limiting: prevents exponential code size explosion.
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _n(v): return ast.Constant(value=v)
def _binop(l, op, r): return ast.BinOp(left=l, op=op(), right=r)
def _unop(op, x):     return ast.UnaryOp(op=op(), operand=x)


def _mba_add_v1(a, b):
    """a + b ≡ (a ^ b) + ((a & b) << 1)"""
    return _binop(_binop(a, ast.BitXor, b), ast.Add,
                  _binop(_binop(a, ast.BitAnd, b), ast.LShift, _n(1)))

def _mba_add_v2(a, b):
    """a + b ≡ (a | b) + (a & b)"""
    return _binop(_binop(a, ast.BitOr, b), ast.Add, _binop(a, ast.BitAnd, b))

def _mba_sub_v1(a, b):
    """a - b ≡ (a ^ b) - ((~a & b) << 1)"""
    return _binop(_binop(a, ast.BitXor, b), ast.Sub,
                  _binop(_binop(_unop(ast.Invert, a), ast.BitAnd, b),
                         ast.LShift, _n(1)))

def _mba_xor_v1(a, b):
    """a ^ b ≡ (a + b) - ((a & b) << 1)"""
    return _binop(_binop(a, ast.Add, b), ast.Sub,
                  _binop(_binop(a, ast.BitAnd, b), ast.LShift, _n(1)))

def _mba_and_v1(a, b):
    """a & b ≡ ((a + b) - (a ^ b)) >> 1"""
    return _binop(_binop(_binop(a, ast.Add, b), ast.Sub,
                         _binop(a, ast.BitXor, b)),
                  ast.RShift, _n(1))

def _mba_or_v1(a, b):
    """a | b ≡ (a ^ b) + (a & b)"""
    return _binop(_binop(a, ast.BitXor, b), ast.Add, _binop(a, ast.BitAnd, b))

def _mba_invert(a):
    """~a ≡ (-a) - 1"""
    return _binop(_unop(ast.USub, a), ast.Sub, _n(1))

# constant obfuscation: n → (n ^ K) ^ K
def _mba_const(n: int) -> ast.expr:
    k = random.randint(1, 0xFFFF)
    return _binop(_binop(_n(n), ast.BitXor, _n(k)), ast.BitXor, _n(k))

# constant: n → (n + K) - K
def _mba_const_v2(n: int) -> ast.expr:
    k = random.randint(1, 0xFFFF)
    return _binop(_binop(_n(n), ast.Add, _n(k)), ast.Sub, _n(k))


_ADD_VARIANTS = [_mba_add_v1, _mba_add_v2]
_SUB_VARIANTS = [_mba_sub_v1]
_XOR_VARIANTS = [_mba_xor_v1]
_AND_VARIANTS = [_mba_and_v1]
_OR_VARIANTS  = [_mba_or_v1]
_CONST_VARIANTS = [_mba_const, _mba_const_v2]


class _MBATransformer(ast.NodeTransformer):
    def __init__(self, density: float, max_depth: int, do_consts: bool):
        self.density   = density
        self.max_depth = max_depth
        self.do_consts = do_consts
        self.count     = 0
        self._depth    = 0

    def _should_transform(self) -> bool:
        return self._depth < self.max_depth and random.random() < self.density

    def visit_BinOp(self, node: ast.BinOp) -> ast.expr:
        self._depth += 1
        self.generic_visit(node)  # recurse first
        self._depth -= 1

        if not self._should_transform():
            return node

        # Safety guard: only transform if at least one operand is a literal
        # integer constant. This prevents accidentally transforming string
        # concatenation (a+b where a,b are strings) into broken code.
        def _is_int_const(n):
            return (isinstance(n, ast.Constant) and
                    isinstance(n.value, int) and
                    not isinstance(n.value, bool))

        def _is_int_expr(n):
            # Recursively check if the node is "int-safe"
            # (constant, binop of int ops, unary of int)
            if _is_int_const(n): return True
            if isinstance(n, ast.BinOp):
                return type(n.op) in (
                    ast.Add, ast.Sub, ast.Mult, ast.BitXor,
                    ast.BitAnd, ast.BitOr, ast.LShift, ast.RShift,
                    ast.Mod, ast.FloorDiv)
            if isinstance(n, ast.UnaryOp):
                return type(n.op) in (ast.USub, ast.UAdd, ast.Invert)
            return False

        l, r = node.left, node.right
        op   = type(node.op)

        # For ADD/SUB: only transform if at least one side is clearly int
        if op in (ast.Add, ast.Sub):
            if not (_is_int_const(l) or _is_int_const(r) or
                    (_is_int_expr(l) and _is_int_expr(r))):
                return node

        new = None
        if op is ast.Add:
            new = random.choice(_ADD_VARIANTS)(l, r)
        elif op is ast.Sub:
            new = random.choice(_SUB_VARIANTS)(l, r)
        elif op is ast.BitXor:
            new = random.choice(_XOR_VARIANTS)(l, r)
        elif op is ast.BitAnd:
            new = random.choice(_AND_VARIANTS)(l, r)
        elif op is ast.BitOr:
            new = random.choice(_OR_VARIANTS)(l, r)

        if new is not None:
            self.count += 1
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            return new
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.expr:
        self.generic_visit(node)
        if isinstance(node.op, ast.Invert) and self._should_transform():
            new = _mba_invert(node.operand)
            self.count += 1
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            return new
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if (self.do_consts and
                isinstance(node.value, int) and
                not isinstance(node.value, bool) and
                abs(node.value) > 1 and
                abs(node.value) < 0x7FFFFFFF and
                self._should_transform()):
            new = random.choice(_CONST_VARIANTS)(node.value)
            self.count += 1
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            return new
        return node


class MBAPass(ObfPass):
    name        = "mba"
    phase       = 2
    description = "Mixed Boolean-Arithmetic: replace ops with MBA equivalents"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            density   = self.opts.get("density",   0.55)
            max_depth = self.opts.get("max_depth",  3)
            do_consts = self.opts.get("constants",  True)
            tree = ast.parse(code)
            t    = _MBATransformer(density, max_depth, do_consts)
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(ast.unparse(tree),
                            message=f"applied {t.count} MBA transform(s)",
                            count=t.count)
        except Exception as exc:
            return self._err(code, exc)
