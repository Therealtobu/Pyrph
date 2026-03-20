"""
FunctionSplitter – splits each function into N fragments called via a dispatcher.

Original:
    def foo(x):
        a = x + 1
        b = a * 2
        return b

Becomes:
    def foo__frag_0(x):      a = x + 1; return (a,)
    def foo__frag_1(__s):    b = __s[0] * 2; return b
    def foo(__d, x):
        return foo__frag_1(foo__frag_0(x))
"""
import ast
import itertools
import math

_ctr = itertools.count(1)
_SPLIT_SIZE = 3   # statements per fragment


class FunctionSplitter(ast.NodeTransformer):

    def transform(self, tree: ast.AST) -> ast.AST:
        self._new_defs: list[ast.FunctionDef] = []
        new_tree = self.visit(tree)
        # Inject generated fragment functions at module level
        if isinstance(new_tree, ast.Module):
            new_tree.body[:0] = self._new_defs
        return new_tree

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        if len(node.body) <= _SPLIT_SIZE:
            return node  # too small
        return self._split(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _split(self, node: ast.FunctionDef) -> ast.FunctionDef:
        body     = node.body
        args_ids = [a.arg for a in node.args.args]
        tag      = next(_ctr)

        # Split body into chunks
        chunks   = [body[i:i+_SPLIT_SIZE] for i in range(0, len(body), _SPLIT_SIZE)]
        frag_names = [f"{node.name}__frag_{tag}_{i}" for i in range(len(chunks))]
        state_var  = "__fs"

        frag_defs: list[ast.FunctionDef] = []

        for i, (chunk, fname) in enumerate(zip(chunks, frag_names)):
            is_last = (i == len(chunks) - 1)

            # Compute free vars that need to be passed
            if i == 0:
                frag_args = ast.arguments(
                    posonlyargs=[], args=[ast.arg(arg=a) for a in args_ids],
                    vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]
                )
            else:
                frag_args = ast.arguments(
                    posonlyargs=[], args=[ast.arg(arg=state_var)],
                    vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]
                )

            if not is_last:
                # Collect assigned names to pass forward
                assigned = _collect_stores(chunk)
                tup = ast.Tuple(
                    elts=[ast.Name(id=n, ctx=ast.Load()) for n in assigned],
                    ctx=ast.Load(),
                )
                ret = ast.Return(value=tup)
                ast.fix_missing_locations(ret)
                frag_body = list(chunk) + [ret]
            else:
                frag_body = list(chunk)

            frag_def = ast.FunctionDef(
                name=fname, args=frag_args,
                body=frag_body, decorator_list=[], returns=None,
                lineno=node.lineno, col_offset=node.col_offset,
            )
            ast.fix_missing_locations(frag_def)
            frag_defs.append(frag_def)
            self._new_defs.append(frag_def)

        # Build dispatcher: chain calls
        call: ast.expr = ast.Call(
            func=ast.Name(id=frag_names[0], ctx=ast.Load()),
            args=[ast.Name(id=a, ctx=ast.Load()) for a in args_ids],
            keywords=[],
        )
        for fname in frag_names[1:]:
            call = ast.Call(
                func=ast.Name(id=fname, ctx=ast.Load()),
                args=[call], keywords=[],
            )
        ast.fix_missing_locations(call)

        dispatch_body = [ast.Return(value=call)]
        new_node = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=dispatch_body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            lineno=node.lineno, col_offset=node.col_offset,
        )
        ast.fix_missing_locations(new_node)
        return new_node


def _collect_stores(stmts: list[ast.stmt]) -> list[str]:
    names = []
    class _V(ast.NodeVisitor):
        def visit_Name(self, n):
            if isinstance(n.ctx, ast.Store) and n.id not in names:
                names.append(n.id)
    v = _V()
    for s in stmts:
        v.visit(s)
    return names or ["__none"]
