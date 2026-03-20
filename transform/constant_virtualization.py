"""
ConstantVirtualizer – replaces numeric constants with runtime-decoded references.

A module-level encrypted constant table is injected:
  __CV = [enc0, enc1, ...]
Each constant n becomes: __CV[i] ^ __CVK

The XOR key (__CVK) is computed at runtime to prevent static extraction.
"""
import ast
import random
import itertools

_ctr  = itertools.count(0)
_CVTABLE = "__CV"
_CVKEY   = "__CVK"


class ConstantVirtualizer(ast.NodeTransformer):

    def __init__(self):
        self._entries: list[tuple[int, int]] = []  # (encoded, key)
        self._key = random.randint(0x1000, 0xFFFF)

    def transform(self, tree: ast.AST) -> ast.AST:
        self._entries.clear()
        self._key = random.randint(0x1000, 0xFFFF)
        new_tree = self.visit(tree)
        self._inject(new_tree)
        return new_tree

    def _register(self, value: int) -> int:
        encoded = value ^ self._key
        idx = len(self._entries)
        self._entries.append((encoded, self._key))
        return idx

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            idx = self._register(node.value)
            # __CV[idx] ^ __CVK
            ref = ast.BinOp(
                left=ast.Subscript(
                    value=ast.Name(id=_CVTABLE, ctx=ast.Load()),
                    slice=ast.Constant(value=idx),
                    ctx=ast.Load(),
                ),
                op=ast.BitXor(),
                right=ast.Name(id=_CVKEY, ctx=ast.Load()),
            )
            ast.copy_location(ref, node)
            ast.fix_missing_locations(ref)
            return ref
        return node

    def _inject(self, tree: ast.AST):
        if not isinstance(tree, ast.Module) or not self._entries:
            return

        # __CVK = <key>
        key_assign = ast.Assign(
            targets=[ast.Name(id=_CVKEY, ctx=ast.Store())],
            value=ast.Constant(value=self._key),
            lineno=1, col_offset=0,
        )
        # __CV = [enc0, enc1, ...]
        table_assign = ast.Assign(
            targets=[ast.Name(id=_CVTABLE, ctx=ast.Store())],
            value=ast.List(
                elts=[ast.Constant(value=e[0]) for e in self._entries],
                ctx=ast.Load(),
            ),
            lineno=1, col_offset=0,
        )
        ast.fix_missing_locations(key_assign)
        ast.fix_missing_locations(table_assign)
        tree.body[:0] = [key_assign, table_assign]
