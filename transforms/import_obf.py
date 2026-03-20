"""
transforms/import_obf.py
=========================
ImportObfPass — replace import statements with __import__() calls.

  import os           → _xyz = __import__('os')
  from os import path → path = __import__('os').path
"""
from __future__ import annotations
import ast
import random
import string
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _rn(n=6) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0,n-1)
    return "_" + raw[:pos]+random.choice(letters)+raw[pos:]


class _ImportTransformer(ast.NodeTransformer):
    def __init__(self):
        self.count = 0

    def visit_Import(self, node):
        stmts = []
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            call  = ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[ast.Constant(value=alias.name)],
                keywords=[])
            assign = ast.Assign(
                targets=[ast.Name(id=local, ctx=ast.Store())],
                value=call, lineno=node.lineno, col_offset=node.col_offset)
            ast.fix_missing_locations(assign)
            stmts.append(assign)
            self.count += 1
        return stmts if len(stmts) > 1 else stmts[0]

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        stmts = []
        for alias in node.names:
            local = alias.asname or alias.name
            # __import__(mod).attr  OR for submodule: getattr(__import__(mod), attr)
            base_call = ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[ast.Constant(value=mod)], keywords=[])
            val = ast.Attribute(value=base_call, attr=alias.name, ctx=ast.Load())
            assign = ast.Assign(
                targets=[ast.Name(id=local, ctx=ast.Store())],
                value=val, lineno=node.lineno, col_offset=node.col_offset)
            ast.fix_missing_locations(assign)
            stmts.append(assign)
            self.count += 1
        return stmts if len(stmts) > 1 else stmts[0]


class ImportObfPass(ObfPass):
    name        = "import_obf"
    phase       = 2
    description = "Replace import statements with __import__() calls"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            tree = ast.parse(code)
            t    = _ImportTransformer()
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(ast.unparse(tree),
                            message=f"obfuscated {t.count} import(s)",
                            count=t.count)
        except Exception as exc:
            return self._err(code, exc)
