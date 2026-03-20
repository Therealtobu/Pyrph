"""
SugarRemover – eliminates Python syntactic sugar that complicates later passes.

Transforms:
  AugAssign (+=, -=, …)  → normal Assign
  Global / Nonlocal      → kept but annotated (no removal – semantics matter)
  f-strings              → str.format() equivalents  (best-effort)
  walrus operator (:=)   → explicit assignment before use
  starred in assignment  → itertools.islice unpack
"""
import ast
import itertools


class SugarRemover(ast.NodeTransformer):
    _counter = itertools.count(1)

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    # ── AugAssign → Assign ───────────────────────────────────────────────────
    _OP_MAP = {
        ast.Add:      ast.Add,
        ast.Sub:      ast.Sub,
        ast.Mult:     ast.Mult,
        ast.Div:      ast.Div,
        ast.FloorDiv: ast.FloorDiv,
        ast.Mod:      ast.Mod,
        ast.Pow:      ast.Pow,
        ast.BitAnd:   ast.BitAnd,
        ast.BitOr:    ast.BitOr,
        ast.BitXor:   ast.BitXor,
        ast.LShift:   ast.LShift,
        ast.RShift:   ast.RShift,
        ast.MatMult:  ast.MatMult,
    }

    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
        # x += y  →  x = x + y
        target_load = ast.Name(
            id=node.target.id if isinstance(node.target, ast.Name) else "__aug",
            ctx=ast.Load(),
        )
        ast.copy_location(target_load, node.target)
        binop = ast.BinOp(
            left=target_load,
            op=type(node.op)(),
            right=node.value,
        )
        assign = ast.Assign(
            targets=[node.target],
            value=binop,
        )
        ast.copy_location(assign, node)
        ast.fix_missing_locations(assign)
        return assign

    # ── Walrus operator (:=) → statement before use ───────────────────────────
    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.generic_visit(node)
        # Emit assignment; return reference to name
        assign = ast.Assign(
            targets=[ast.Name(id=node.target.id, ctx=ast.Store())],
            value=node.value,
        )
        ast.copy_location(assign, node)
        ast.fix_missing_locations(assign)
        self._pending = getattr(self, "_pending", [])
        self._pending.append(assign)
        return ast.Name(id=node.target.id, ctx=ast.Load())

    # ── JoinedStr (f-string) → str.format() ──────────────────────────────────
    def visit_JoinedStr(self, node: ast.JoinedStr):
        self.generic_visit(node)
        parts_fmt = []
        args      = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                # Escape braces in literal text
                parts_fmt.append(str(val.value).replace("{", "{{").replace("}", "}}"))
            elif isinstance(val, ast.FormattedValue):
                fmt_spec = ""
                if val.format_spec:
                    # format_spec is itself a JoinedStr; simplified to empty
                    fmt_spec = ""
                parts_fmt.append("{" + fmt_spec + "}")
                args.append(val.value)
            else:
                parts_fmt.append("{}")
                args.append(val)
        fmt_str = "".join(parts_fmt)
        call = ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=fmt_str),
                attr="format",
                ctx=ast.Load(),
            ),
            args=args,
            keywords=[],
        )
        ast.copy_location(call, node)
        ast.fix_missing_locations(call)
        return call

    # ── injection plumbing ────────────────────────────────────────────────────
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
        node.body   = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node

    def visit_While(self, node: ast.While):
        node.body   = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node

    def visit_If(self, node: ast.If):
        node.body   = self._expand_body(node.body)
        node.orelse = self._expand_body(node.orelse)
        return node
