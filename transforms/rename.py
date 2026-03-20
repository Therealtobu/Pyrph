"""
transforms/rename.py
=====================
RenamePass — rename all user-defined identifiers to random names.

v2 improvements:
- Uses truly random names of varying length (not sequential _0x0001)
- Mixes hex chars with random letters so it doesn't look like pure hex
- Handles global/nonlocal declarations correctly
- Preserves builtins, dunder names, keywords
"""
from __future__ import annotations
import ast
import keyword
import random
import string
from ..core.base   import ObfPass
from ..core.result import ObfResult


_KEYWORDS = frozenset(keyword.kwlist)
_BUILTINS = frozenset([
    "print","input","len","range","int","str","float","bool",
    "list","dict","set","tuple","type","bytes","bytearray",
    "open","super","object","property","staticmethod","classmethod",
    "enumerate","zip","map","filter","sorted","reversed",
    "sum","min","max","abs","round","pow","divmod","hash",
    "id","hex","oct","bin","ord","chr","repr","format",
    "iter","next","callable","isinstance","issubclass",
    "hasattr","getattr","setattr","delattr","vars","dir",
    "globals","locals","exec","eval","compile",
    "Exception","ValueError","TypeError","KeyError","IndexError",
    "AttributeError","RuntimeError","StopIteration","OSError",
    "IOError","FileNotFoundError","NotImplementedError","PermissionError",
    "OverflowError","ZeroDivisionError","ImportError","RecursionError",
    "MemoryError","SystemExit","KeyboardInterrupt","BaseException",
    "AssertionError","NameError","UnboundLocalError","GeneratorExit",
    "self","cls",
    "os","sys","re","json","math","time","random","pathlib",
    "collections","itertools","functools","threading","subprocess",
    "argparse","logging","copy","io","abc","typing","inspect",
    "dis","ast","struct","base64","hashlib","hmac","secrets",
    "marshal","types","ctypes","importlib",
    "True","False","None",
    "__import__","__builtins__","__all__","__name__","__file__",
    "__doc__","__package__","__spec__","__loader__","__init__",
    "__new__","__del__","__repr__","__str__","__len__","__iter__",
    "__next__","__getitem__","__setitem__","__delitem__","__contains__",
    "__call__","__enter__","__exit__","__class__","__dict__",
    "__bases__","__mro__","__slots__","__annotations__",
])
_SKIP = _KEYWORDS | _BUILTINS


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


class _RandomNameGen:
    """Generates unique random identifiers that don't look like pure hex."""
    _LETTERS = "abcdefghjkmnpqrstuvwxyz"
    _HEX     = "abcdef0123456789"
    _MIX     = _HEX + "ghjkmnpqrtuvwx"

    def __init__(self, prefix: str = "_"):
        self._prefix = prefix
        self._used: set = set()

    def next(self) -> str:
        while True:
            n    = random.randint(5, 9)
            raw  = list(random.choices(self._HEX, k=n))
            # inject 1 random non-hex letter so it doesn't look like pure hex
            pos  = random.randint(0, n-1)
            raw[pos] = random.choice(self._LETTERS)
            name = self._prefix + "".join(raw)
            if name not in self._used:
                self._used.add(name)
                return name


class _DefCollector(ast.NodeVisitor):
    """Collect all user-defined identifier names in a tree."""
    def __init__(self):
        self.candidates: set = set()
        self._scope_stack: list = [set()]

    def _add(self, name: str):
        if name and name not in _SKIP and not _is_dunder(name):
            self.candidates.add(name)

    def visit_FunctionDef(self, node):
        self._add(node.name)
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self._add(arg.arg)
        if node.args.vararg:   self._add(node.args.vararg.arg)
        if node.args.kwarg:    self._add(node.args.kwarg.arg)
        self.generic_visit(node)
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._add(node.name)
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._add(node.id)

    def visit_Global(self, node):
        for n in node.names: self._add(n)

    def visit_Nonlocal(self, node):
        for n in node.names: self._add(n)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self._add(local)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self._add(local)


class _Renamer(ast.NodeTransformer):
    def __init__(self, rename_map: dict):
        self._map = rename_map

    def visit_Name(self, node):
        if node.id in self._map:
            node.id = self._map[node.id]
        return node

    def visit_FunctionDef(self, node):
        if node.name in self._map:
            node.name = self._map[node.name]
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            if arg.arg in self._map:
                arg.arg = self._map[arg.arg]
        if node.args.vararg and node.args.vararg.arg in self._map:
            node.args.vararg.arg = self._map[node.args.vararg.arg]
        if node.args.kwarg and node.args.kwarg.arg in self._map:
            node.args.kwarg.arg = self._map[node.args.kwarg.arg]
        self.generic_visit(node)
        return node
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if node.name in self._map:
            node.name = self._map[node.name]
        self.generic_visit(node)
        return node

    def visit_Global(self, node):
        node.names = [self._map.get(n, n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._map.get(n, n) for n in node.names]
        return node

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname and alias.asname in self._map:
                alias.asname = self._map[alias.asname]
            elif not alias.asname:
                local = alias.name.split(".")[0]
                if local in self._map:
                    alias.asname = self._map[local]
        return node

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.asname and alias.asname in self._map:
                alias.asname = self._map[alias.asname]
            elif not alias.asname and alias.name in self._map:
                alias.asname = self._map[alias.name]
        return node


class RenamePass(ObfPass):
    name        = "rename"
    phase       = 1
    description = "Rename identifiers to random names"

    def run(self, code: str) -> ObfResult:
        if not self.enabled:
            return self._skip(code)
        try:
            prefix   = self.opts.get("prefix", "_")
            tree     = ast.parse(code)
            collector = _DefCollector()
            collector.visit(tree)
            gen = _RandomNameGen(prefix=prefix)
            rename_map = {name: gen.next() for name in sorted(collector.candidates)}
            new_tree   = _Renamer(rename_map).visit(tree)
            ast.fix_missing_locations(new_tree)
            result = ast.unparse(new_tree)
            return self._ok(result,
                            message=f"renamed {len(rename_map)} identifier(s)",
                            count=len(rename_map))
        except Exception as exc:
            return self._err(code, exc)
