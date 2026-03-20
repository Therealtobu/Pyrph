"""
StringLifter – moves all string literals into a module-level table.

  s = "hello"
→ __ST = {0: 'hello', ...}   (added at module top)
  s = __ST[0]
"""
import ast
import itertools

_ctr = itertools.count(0)
_TABLE_NAME = "__ST"


class StringLifter(ast.NodeTransformer):

    def __init__(self):
        self._table: dict[str, int] = {}   # string → table index

    def transform(self, tree: ast.AST) -> ast.AST:
        self._table.clear()
        new_tree = self.visit(tree)
        self._inject_table(new_tree)
        return new_tree

    def _intern(self, s: str) -> int:
        if s not in self._table:
            self._table[s] = next(_ctr)
        return self._table[s]

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and len(node.value) > 0:
            idx = self._intern(node.value)
            ref = ast.Subscript(
                value=ast.Name(id=_TABLE_NAME, ctx=ast.Load()),
                slice=ast.Constant(value=idx),
                ctx=ast.Load(),
            )
            ast.copy_location(ref, node)
            ast.fix_missing_locations(ref)
            return ref
        return node

    def _inject_table(self, tree: ast.Module):
        if not isinstance(tree, ast.Module):
            return
        if not self._table:
            return

        # Build {idx: string, ...}
        keys   = [ast.Constant(value=v) for v in self._table.values()]
        values = [ast.Constant(value=k) for k in self._table.keys()]
        table_dict = ast.Dict(keys=keys, values=values)
        assign = ast.Assign(
            targets=[ast.Name(id=_TABLE_NAME, ctx=ast.Store())],
            value=table_dict,
            lineno=1, col_offset=0,
        )
        ast.fix_missing_locations(assign)
        tree.body.insert(0, assign)
