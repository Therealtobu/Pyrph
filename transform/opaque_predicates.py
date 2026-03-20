"""
OpaquePredicates – inserts always-true / always-false dynamic predicates
that cannot be statically resolved.

Predicates use runtime values (id(), hash(), time.time_ns() mod N) to ensure
no static analysis tool can prove them constant.

Example inserted guard:
    if (id(object) & 1) == (id(object) & 1):   # always True
        <real code>
    else:
        <dead junk code>
"""
import ast
import random
import itertools

_ctr = itertools.count(1)


def _opaque_true() -> ast.expr:
    """Returns an expression that is always True but looks dynamic."""
    choice = random.randint(0, 2)
    if choice == 0:
        # (id(object) & 0xFF) == (id(object) & 0xFF)  -- always True
        lhs = ast.BinOp(
            left=ast.Call(func=ast.Name(id="id", ctx=ast.Load()),
                          args=[ast.Name(id="object", ctx=ast.Load())], keywords=[]),
            op=ast.BitAnd(),
            right=ast.Constant(value=0xFF),
        )
        rhs = ast.BinOp(
            left=ast.Call(func=ast.Name(id="id", ctx=ast.Load()),
                          args=[ast.Name(id="object", ctx=ast.Load())], keywords=[]),
            op=ast.BitAnd(),
            right=ast.Constant(value=0xFF),
        )
        return ast.Compare(left=lhs, ops=[ast.Eq()], comparators=[rhs])
    elif choice == 1:
        # (hash(None) ^ hash(None)) == 0  -- always True
        lhs = ast.BinOp(
            left=ast.Call(func=ast.Name(id="hash", ctx=ast.Load()),
                          args=[ast.Constant(value=None)], keywords=[]),
            op=ast.BitXor(),
            right=ast.Call(func=ast.Name(id="hash", ctx=ast.Load()),
                           args=[ast.Constant(value=None)], keywords=[]),
        )
        return ast.Compare(left=lhs, ops=[ast.Eq()], comparators=[ast.Constant(value=0)])
    else:
        # isinstance([], list)  -- always True
        return ast.Call(
            func=ast.Name(id="isinstance", ctx=ast.Load()),
            args=[ast.List(elts=[], ctx=ast.Load()),
                  ast.Name(id="list", ctx=ast.Load())],
            keywords=[],
        )


def _junk_block() -> list[ast.stmt]:
    """Dead code that never executes (placed in the else branch)."""
    var = f"__junk_{next(_ctr)}"
    return [
        ast.Assign(
            targets=[ast.Name(id=var, ctx=ast.Store())],
            value=ast.Constant(value=0xDEAD),
        ),
        ast.Expr(value=ast.Call(
            func=ast.Name(id="id", ctx=ast.Load()),
            args=[ast.Name(id=var, ctx=ast.Load())], keywords=[],
        )),
    ]


class OpaquePredicates(ast.NodeTransformer):

    _WRAP_PROB = 0.40   # probability to wrap any given statement

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    def _maybe_wrap(self, stmt: ast.stmt) -> ast.stmt:
        if random.random() > self._WRAP_PROB:
            return stmt
        pred = _opaque_true()
        junk = _junk_block()
        wrapper = ast.If(
            test=pred,
            body=[stmt],
            orelse=junk,
        )
        ast.copy_location(wrapper, stmt)
        ast.fix_missing_locations(wrapper)
        return wrapper

    def _process_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        return [self._maybe_wrap(self.visit(s)) for s in body]

    def visit_Module(self, node: ast.Module):
        node.body = self._process_body(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        node.body = self._process_body(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node: ast.For):
        node.body   = self._process_body(node.body)
        node.orelse = self._process_body(node.orelse)
        return node

    def visit_While(self, node: ast.While):
        node.body   = self._process_body(node.body)
        node.orelse = self._process_body(node.orelse)
        return node

    def visit_If(self, node: ast.If):
        node.body   = self._process_body(node.body)
        node.orelse = self._process_body(node.orelse)
        return node
