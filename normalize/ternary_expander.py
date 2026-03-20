"""
TernaryExpander – replaces IfExp (ternary) with explicit if/else blocks.

  y = a if cond else b
→ if cond:
      __te_1 = a
  else:
      __te_1 = b
  y = __te_1
"""
import ast
import itertools


class TernaryExpander(ast.NodeTransformer):
    _counter = itertools.count(1)

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    def _tmp(self):
        return f"__te_{next(self._counter)}"

    def visit_IfExp(self, node: ast.IfExp):
        self.generic_visit(node)
        tmp = self._tmp()

        if_stmt = ast.If(
            test=node.test,
            body=[ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=node.body,
            )],
            orelse=[ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=node.orelse,
            )],
        )
        ast.copy_location(if_stmt, node)
        ast.fix_missing_locations(if_stmt)

        self._pending = getattr(self, "_pending", [])
        self._pending.append(if_stmt)
        return ast.Name(id=tmp, ctx=ast.Load())

    def _flush(self):
        items = getattr(self, "_pending", [])
        self._pending = []
        return items

    def _expand_body(self, body):
        result = []
        for stmt in body:
            visited = self.visit(stmt)
            pending = self._flush()
            result.extend(pending)
            result.append(visited)
        return result

    def visit_Module(self, node: ast.Module):
        node.body = self._expand_body(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        node.body = self._expand_body(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node: ast.For):
        node.body = self._expand_body(node.body)
        return node

    def visit_While(self, node: ast.While):
        node.body = self._expand_body(node.body)
        return node

    def visit_If(self, node: ast.If):
        node.body   = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node
