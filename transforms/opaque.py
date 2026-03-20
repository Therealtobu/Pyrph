"""
transforms/opaque.py
=====================
OpaquePass — inject mathematically opaque predicates.

Uses number-theoretic predicates that symbolic solvers (Z3, Ghidra)
cannot trivially resolve:

  Always-True:
    pow(a, p-1, p) == 1          Fermat's little theorem
    (n*(n+1)) % 2 == 0           consecutive integers always even
    (a*a + b*b) % 4 != 3         sum of squares never ≡ 3 (mod 4)
    (n | ~n) == -1               bitwise tautology

  Always-False:
    pow(a, p-1, p) != 1
    n*n < 0
    (a*a + b*b) % 4 == 3
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


_PRIMES = [17,19,23,29,31,37,41,43,47,53,59,61,67,71,73]


def _n(v): return ast.Constant(value=v)
def _binop(l,op,r): return ast.BinOp(left=l,op=op(),right=r)
def _cmp(l,op,r):   return ast.Compare(left=l,ops=[op()],comparators=[r])
def _call(fn,*args): return ast.Call(func=ast.Name(id=fn,ctx=ast.Load()),args=list(args),keywords=[])


# ── Always-True pool ─────────────────────────────────────────────────────

def _fermat_true():
    p = random.choice(_PRIMES); a = random.randint(2,p-1)
    return _cmp(_call("pow",_n(a),_n(p-1),_n(p)), ast.Eq, _n(1))

def _consec_even_true():
    n = random.randint(100,9999)
    inner = _binop(_n(n), ast.Mult, _binop(_n(n),ast.Add,_n(1)))
    return _cmp(_binop(inner,ast.Mod,_n(2)), ast.Eq, _n(0))

def _sos_mod4_true():
    a = random.randint(1,999); b = random.randint(1,999)
    ss = _binop(_binop(_n(a),ast.Mult,_n(a)), ast.Add, _binop(_n(b),ast.Mult,_n(b)))
    return _cmp(_binop(ss,ast.Mod,_n(4)), ast.NotEq, _n(3))

def _or_inv_true():
    n = random.randint(1,0xFFFF)
    bor = _binop(_n(n), ast.BitOr, ast.UnaryOp(op=ast.Invert(),operand=_n(n)))
    return _cmp(bor, ast.Eq, _n(-1))

def _xor_self_true():
    n = random.randint(1,0xFFFF)
    return _cmp(_binop(_n(n),ast.BitXor,_n(n)), ast.Eq, _n(0))


# ── Always-False pool ────────────────────────────────────────────────────

def _fermat_false():
    p = random.choice(_PRIMES); a = random.randint(2,p-1)
    return _cmp(_call("pow",_n(a),_n(p-1),_n(p)), ast.NotEq, _n(1))

def _sq_neg_false():
    n = random.randint(1,0xFFFF)
    return _cmp(_binop(_n(n),ast.Mult,_n(n)), ast.Lt, _n(0))

def _sos_mod4_false():
    a = random.randint(1,999); b = random.randint(1,999)
    ss = _binop(_binop(_n(a),ast.Mult,_n(a)), ast.Add, _binop(_n(b),ast.Mult,_n(b)))
    return _cmp(_binop(ss,ast.Mod,_n(4)), ast.Eq, _n(3))

def _consec_even_false():
    n = random.randint(100,9999)
    inner = _binop(_n(n), ast.Mult, _binop(_n(n),ast.Add,_n(1)))
    return _cmp(_binop(inner,ast.Mod,_n(2)), ast.NotEq, _n(0))


_TRUE_POOL  = [_fermat_true, _consec_even_true, _sos_mod4_true, _or_inv_true, _xor_self_true]
_FALSE_POOL = [_fermat_false, _sq_neg_false, _sos_mod4_false, _consec_even_false]


class _OpaqueTransformer(ast.NodeTransformer):
    def __init__(self, density: float):
        self.density = density
        self.count   = 0

    def _wrap(self, stmt):
        if random.random() > self.density:
            return stmt
        self.count += 1
        pred = random.choice(_TRUE_POOL)()
        orelse = []
        if random.random() < 0.35:
            orelse = [ast.If(test=random.choice(_FALSE_POOL)(),
                             body=[ast.Pass()], orelse=[])]
        new = ast.If(test=pred, body=[stmt], orelse=orelse)
        ast.copy_location(new, stmt)
        ast.fix_missing_locations(new)
        return new

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = [self._wrap(s) for s in node.body]
        return node
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        self.generic_visit(node)
        if not node.orelse and random.random() < self.density * 0.4:
            node.orelse = [ast.If(test=random.choice(_FALSE_POOL)(),
                                  body=[ast.Pass()], orelse=[])]
            self.count += 1
        return node


class OpaquePass(ObfPass):
    name        = "opaque"
    phase       = 2
    description = "Inject Fermat/sum-of-squares opaque predicates"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            density = self.opts.get("density", 0.35)
            tree    = ast.parse(code)
            t       = _OpaqueTransformer(density)
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(ast.unparse(tree),
                            message=f"injected {t.count} opaque predicate(s)",
                            count=t.count)
        except Exception as exc:
            return self._err(code, exc)
