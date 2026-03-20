"""
ComprehensionExpander – expands list/set/dict comprehensions into explicit for-loops.

  [x*2 for x in items if x > 0]
→ __lc_1 = []
  for x in items:
      if x > 0:
          __lc_1.append(x * 2)
"""
import ast
import itertools


class ComprehensionExpander(ast.NodeTransformer):
    _counter = itertools.count(1)

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _tmp(self):
        return f"__lc_{next(self._counter)}"

    def _build_for_loop(self, generators, inner_stmts, node):
        """Recursively build nested for/if from a list of comprehension generators."""
        if not generators:
            return inner_stmts
        gen = generators[0]
        body = self._build_for_loop(generators[1:], inner_stmts, node)
        # Wrap with ifs
        for cond in reversed(gen.ifs):
            body = [ast.If(test=cond, body=body, orelse=[])]
        loop = ast.For(
            target=gen.target,
            iter=gen.iter,
            body=body,
            orelse=[],
        )
        ast.copy_location(loop, node)
        ast.fix_missing_locations(loop)
        return [loop]

    # ── ListComp ─────────────────────────────────────────────────────────────
    def visit_ListComp(self, node: ast.ListComp):
        self.generic_visit(node)
        tmp = self._tmp()
        init = ast.Assign(
            targets=[ast.Name(id=tmp, ctx=ast.Store())],
            value=ast.List(elts=[], ctx=ast.Load()),
        )
        append = ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id=tmp, ctx=ast.Load()),
                attr="append", ctx=ast.Load(),
            ),
            args=[node.elt], keywords=[],
        ))
        stmts = self._build_for_loop(node.generators, [append], node)
        self._inject([init] + stmts)
        return ast.Name(id=tmp, ctx=ast.Load())

    # ── SetComp ──────────────────────────────────────────────────────────────
    def visit_SetComp(self, node: ast.SetComp):
        self.generic_visit(node)
        tmp = self._tmp()
        init = ast.Assign(
            targets=[ast.Name(id=tmp, ctx=ast.Store())],
            value=ast.Call(func=ast.Name(id="set", ctx=ast.Load()), args=[], keywords=[]),
        )
        add = ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id=tmp, ctx=ast.Load()),
                attr="add", ctx=ast.Load(),
            ),
            args=[node.elt], keywords=[],
        ))
        stmts = self._build_for_loop(node.generators, [add], node)
        self._inject([init] + stmts)
        return ast.Name(id=tmp, ctx=ast.Load())

    # ── DictComp ─────────────────────────────────────────────────────────────
    def visit_DictComp(self, node: ast.DictComp):
        self.generic_visit(node)
        tmp = self._tmp()
        init = ast.Assign(
            targets=[ast.Name(id=tmp, ctx=ast.Store())],
            value=ast.Dict(keys=[], values=[]),
        )
        assign_item = ast.Assign(
            targets=[ast.Subscript(
                value=ast.Name(id=tmp, ctx=ast.Load()),
                slice=node.key, ctx=ast.Store(),
            )],
            value=node.value,
        )
        stmts = self._build_for_loop(node.generators, [assign_item], node)
        self._inject([init] + stmts)
        return ast.Name(id=tmp, ctx=ast.Load())

    # ── injection plumbing ────────────────────────────────────────────────────
    def _inject(self, stmts):
        self._pending = getattr(self, "_pending", [])
        self._pending.extend(stmts)

    def _flush(self):
        items = getattr(self, "_pending", [])
        self._pending = []
        return items

    def _expand_body(self, body):
        new_body = []
        for stmt in body:
            visited = self.visit(stmt)
            pending = self._flush()
            new_body.extend(pending)
            new_body.append(visited)
        return new_body

    def visit_Module(self, node: ast.Module):
        node.body = self._expand_body(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        node.body = self._expand_body(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node: ast.For):
        node.body  = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node

    def visit_While(self, node: ast.While):
        node.body  = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node

    def visit_If(self, node: ast.If):
        node.body  = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node
