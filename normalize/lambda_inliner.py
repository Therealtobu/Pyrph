"""
LambdaInliner – converts lambda expressions into named function definitions.

  f = lambda x, y: x + y
→ def __lam_1(x, y): return x + y
  f = __lam_1
"""
import ast
import itertools


class LambdaInliner(ast.NodeTransformer):
    _counter = itertools.count(1)

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    def visit_Lambda(self, node: ast.Lambda) -> ast.AST:
        # Recurse first (nested lambdas)
        self.generic_visit(node)
        name = f"__lam_{next(self._counter)}"
        func_def = ast.FunctionDef(
            name=name,
            args=node.args,
            body=[ast.Return(value=node.body)],
            decorator_list=[],
            returns=None,
        )
        ast.copy_location(func_def, node)
        ast.fix_missing_locations(func_def)
        # Inject the definition into the enclosing module/function body
        # via a module-level stash; actual injection happens in visit_Module/FunctionDef
        self._pending = getattr(self, "_pending", [])
        self._pending.append(func_def)
        return ast.Name(id=name, ctx=ast.Load())

    def _flush_pending(self):
        items = getattr(self, "_pending", [])
        self._pending = []
        return items

    def visit_Module(self, node: ast.Module) -> ast.AST:
        new_body = []
        for stmt in node.body:
            new_body.append(self.visit(stmt))
            new_body[:0] = self._flush_pending()   # inject before current stmt
        node.body = new_body
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        new_body = []
        for stmt in node.body:
            visited = self.visit(stmt)
            pending = self._flush_pending()
            new_body.extend(pending)
            new_body.append(visited)
        node.body = new_body
        return node

    visit_AsyncFunctionDef = visit_FunctionDef
