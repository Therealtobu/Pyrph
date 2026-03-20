"""
transforms/dead_code.py
========================
DeadCodePass — inject unreachable dead branches.

Wraps random statements inside always-false conditions:
    if 4919 * 4919 < 0:
        <dead branch>

Combined with OpaquePass this creates very noisy CFGs.
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _false_cond() -> ast.expr:
    primes = [17,19,23,29,31,37,41,43,47,53]
    p = random.choice(primes); a = random.randint(2,p-1)
    choice = random.randint(0,2)
    if choice == 0:
        n = random.randint(1,0xFFFF)
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=n),op=ast.Mult(),right=ast.Constant(value=n)),
            ops=[ast.Lt()], comparators=[ast.Constant(value=0)])
    elif choice == 1:
        return ast.Compare(
            left=ast.Call(func=ast.Name(id="pow",ctx=ast.Load()),
                          args=[ast.Constant(p-1), ast.Constant(p-1), ast.Constant(p)],
                          keywords=[]),
            ops=[ast.NotEq()], comparators=[ast.Constant(value=1)])
    else:
        n = random.randint(100,9999)
        inner = ast.BinOp(left=ast.Constant(n),op=ast.Mult(),
                          right=ast.BinOp(left=ast.Constant(n),op=ast.Add(),
                                          right=ast.Constant(1)))
        return ast.Compare(
            left=ast.BinOp(left=inner,op=ast.Mod(),right=ast.Constant(2)),
            ops=[ast.NotEq()], comparators=[ast.Constant(0)])


def _dead_stmt() -> ast.stmt:
    """Generate a plausible-looking dead statement."""
    rng = random.Random()
    choices = [
        lambda: ast.Assign(
            targets=[ast.Name(id="_d"+hex(rng.randint(0,0xFFFFFF))[2:], ctx=ast.Store())],
            value=ast.Constant(value=rng.randint(0,0xFFFF)),
            lineno=1, col_offset=0),
        lambda: ast.Pass(),
    ]
    return random.choice(choices)()


class _DeadTransformer(ast.NodeTransformer):
    def __init__(self, density: float):
        self.density = density
        self.count   = 0

    def _inject(self, stmts: list) -> list:
        out = []
        for s in stmts:
            out.append(s)
            if random.random() < self.density:
                ds  = _dead_stmt()
                cond = _false_cond()
                dead = ast.If(test=cond, body=[ds], orelse=[])
                ast.copy_location(dead, s)
                ast.fix_missing_locations(dead)
                out.append(dead)
                self.count += 1
        return out

    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node
    visit_AsyncFunctionDef = visit_FunctionDef


class DeadCodePass(ObfPass):
    name        = "dead_code"
    phase       = 2
    description = "Inject unreachable dead code branches"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            density = self.opts.get("density", 0.25)
            tree    = ast.parse(code)
            t       = _DeadTransformer(density)
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(ast.unparse(tree),
                            message=f"injected {t.count} dead block(s)", count=t.count)
        except Exception as exc:
            return self._err(code, exc)
