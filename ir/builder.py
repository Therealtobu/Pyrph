"""
IRBuilder – converts a normalised+transformed AST into an IRModule.

Visitor pattern: each visit_* method emits IRInstructions into the
current IRBlock.  Control-flow statements create new blocks and connect
them via JUMP / JUMP_IF_TRUE / JUMP_IF_FALSE instructions.
"""
from __future__ import annotations
import ast
from typing import Optional

from .nodes import (
    IROp, IROperand, IRInstruction, IRBlock, IRFunction, IRModule
)

_REG  = lambda n: IROperand("reg",   n)
_VAR  = lambda n: IROperand("var",   n)
_CONST= lambda v: IROperand("const", v)
_LBL  = lambda l: IROperand("label", l)
_STR  = lambda i: IROperand("str_ref", i)
_CREF = lambda i: IROperand("const_ref", i)
_BTIN = lambda n: IROperand("builtin", n)
_CNT  = lambda n: IROperand("count",  n)


class _FuncContext:
    """Per-function build context."""

    def __init__(self, func: IRFunction, module: IRModule):
        self.func   = func
        self.module = module
        self.block  = func.new_block("entry")

    def temp(self) -> str:
        return self.func.new_temp()

    def new_block(self, label: str = None) -> IRBlock:
        return self.func.new_block(label)

    def switch(self, block: IRBlock):
        self.block = block

    def emit(self, op: IROp, dst=None, src=None, label=None, **meta) -> IRInstruction:
        instr = IRInstruction(op=op, dst=dst, src=src or [], label=label, metadata=meta)
        self.block.emit(instr)
        return instr

    def emit_jump(self, target: IRBlock):
        self.emit(IROp.JUMP, label=target.label)
        if target.id not in self.block.successors:
            self.block.successors.append(target.id)
        if self.block.id not in target.predecessors:
            target.predecessors.append(self.block.id)

    def emit_branch(self, cond_reg: str, true_blk: IRBlock, false_blk: IRBlock):
        self.emit(IROp.JUMP_IF_TRUE,  src=[_REG(cond_reg)], label=true_blk.label)
        self.emit(IROp.JUMP_IF_FALSE, src=[_REG(cond_reg)], label=false_blk.label)
        for tgt in (true_blk, false_blk):
            if tgt.id not in self.block.successors:
                self.block.successors.append(tgt.id)
            if self.block.id not in tgt.predecessors:
                tgt.predecessors.append(self.block.id)


class IRBuilder(ast.NodeVisitor):
    """Translates a module-level AST into an IRModule."""

    def __init__(self):
        self._module: IRModule         = IRModule()
        self._ctx:    Optional[_FuncContext] = None   # current function context
        self._loop_exits: list[IRBlock] = []          # stack for break targets

    # ── Public entry ──────────────────────────────────────────────────────────
    def build(self, tree: ast.Module) -> IRModule:
        self.visit(tree)
        return self._module

    # ─────────────────────────────────────────────────────────────────────────
    # Module
    # ─────────────────────────────────────────────────────────────────────────
    def visit_Module(self, node: ast.Module):
        # Create a synthetic __module__ function for top-level code
        fn  = IRFunction(name="__module__", args=[])
        self._module.functions.insert(0, fn)
        self._ctx = _FuncContext(fn, self._module)

        for stmt in node.body:
            self.visit(stmt)

        # Terminate module function
        if not self._ctx.block.is_terminated():
            self._ctx.emit(IROp.RETURN, src=[_CONST(None)])

    # ─────────────────────────────────────────────────────────────────────────
    # Statements
    # ─────────────────────────────────────────────────────────────────────────
    def visit_FunctionDef(self, node: ast.FunctionDef):
        parent_ctx = self._ctx
        args = [a.arg for a in node.args.args]
        # Capture *args and **kwargs as special markers
        if node.args.vararg:
            args.append('*' + node.args.vararg.arg)
        if node.args.kwarg:
            args.append('**' + node.args.kwarg.arg)
        fn   = IRFunction(name=node.name, args=args)
        self._module.functions.append(fn)
        self._ctx = _FuncContext(fn, self._module)

        for stmt in node.body:
            self.visit(stmt)

        if not self._ctx.block.is_terminated():
            self._ctx.emit(IROp.RETURN, src=[_CONST(None)])

        # Restore parent context, emit function reference assignment
        self._ctx = parent_ctx
        tmp = parent_ctx.temp()
        parent_ctx.emit(IROp.LOAD_CONST, dst=_REG(tmp),
                        src=[IROperand("func_ref", node.name)])
        parent_ctx.emit(IROp.STORE_VAR, src=[_REG(tmp), _VAR(node.name)])

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Try(self, node: ast.Try):
        """try/except/finally - emit try body with exception handler."""
        ctx = self._ctx
        except_blk = ctx.new_block("except_entry")
        after_blk  = ctx.new_block("try_after")

        # TRY_ENTER: push exception handler label onto VM exception stack
        # Use src operand (not instruction label) so VM can read handler PC
        ctx.emit(IROp.TRY_ENTER, src=[IROperand("lbl", except_blk.label)])

        # Try body
        for s in node.body:
            self.visit(s)
        if not ctx.block.is_terminated():
            ctx.emit(IROp.TRY_EXIT)          # pop handler - success
            ctx.emit_jump(after_blk)

        # Except handler(s)
        ctx.switch(except_blk)
        ctx.emit(IROp.TRY_EXIT)              # pop handler inside handler
        for handler in node.handlers:
            for s in handler.body:
                self.visit(s)
            if not ctx.block.is_terminated():
                ctx.emit_jump(after_blk)

        # Finally / after
        ctx.switch(after_blk)
        for s in node.finalbody if hasattr(node, 'finalbody') and node.finalbody else []:
            self.visit(s)

    visit_TryStar = visit_Try   # Python 3.11+ ExceptionGroup

    def visit_ClassDef(self, node: ast.ClassDef):
        """Compile class using type(name, (object,), {method: fn, ...})."""
        ctx = self._ctx
        cls_name = node.name

        # Visit method functions (registers them as IR functions)
        method_names = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.visit(item)
                method_names.append(item.name)

        # Load type builtin
        type_reg = ctx.temp()
        ctx.emit(IROp.LOAD_VAR, dst=_REG(type_reg), src=[_VAR("type")])

        # bases = (object,)
        obj_reg = ctx.temp()
        ctx.emit(IROp.LOAD_VAR, dst=_REG(obj_reg), src=[_VAR("object")])
        bases_reg = ctx.temp()
        ctx.emit(IROp.BUILD_LIST, dst=_REG(bases_reg),
                 src=[_REG(obj_reg), IROperand("count", 1)])

        # Build methods dict: {name_str: fn_ref, ...}
        pairs = []
        for mname in method_names:
            nr = ctx.temp()
            idx = self._module.intern_const(mname)
            ctx.emit(IROp.LOAD_CONST, dst=_REG(nr), src=[IROperand("str_ref", idx)])
            vr = ctx.temp()
            ctx.emit(IROp.LOAD_VAR, dst=_REG(vr), src=[_VAR(mname)])
            pairs += [_REG(nr), _REG(vr)]
        dict_reg = ctx.temp()
        ctx.emit(IROp.BUILD_DICT, dst=_REG(dict_reg),
                 src=pairs + [IROperand("count", len(method_names))])

        # cls name string
        cn_reg = ctx.temp()
        cn_idx = self._module.intern_const(cls_name)
        ctx.emit(IROp.LOAD_CONST, dst=_REG(cn_reg), src=[IROperand("str_ref", cn_idx)])

        # type(name, bases, dict) → class object
        cls_reg = ctx.temp()
        ctx.emit(IROp.CALL, dst=_REG(cls_reg),
                 src=[_REG(type_reg), _REG(cn_reg), _REG(bases_reg), _REG(dict_reg)])
        ctx.emit(IROp.STORE_VAR, src=[_REG(cls_reg), _VAR(cls_name)])

    def visit_Return(self, node: ast.Return):
        if node.value:
            val = self._expr(node.value)
            self._ctx.emit(IROp.RETURN, src=[val])
        else:
            self._ctx.emit(IROp.RETURN, src=[_CONST(None)])

    def visit_Assign(self, node: ast.Assign):
        src_op = self._expr(node.value)
        for target in node.targets:
            self._assign_target(target, src_op)

    def visit_AugAssign(self, node: ast.AugAssign):
        # total += i  →  LOAD_VAR total; ADD i; STORE_VAR total
        from .nodes import IROp, IROperand
        ctx = self._ctx
        # Load current value of target
        if isinstance(node.target, ast.Name):
            tgt_name = node.target.id
            cur = ctx.temp()
            ctx.emit(IROp.LOAD_VAR, dst=_REG(cur), src=[_VAR(tgt_name)])
            rhs = self._expr(node.value)
            result = ctx.temp()
            op_map = {
                ast.Add: IROp.ADD, ast.Sub: IROp.SUB, ast.Mult: IROp.MUL,
                ast.Div: IROp.DIV, ast.FloorDiv: IROp.FLOORDIV, ast.Mod: IROp.MOD,
                ast.Pow: IROp.POW, ast.BitAnd: IROp.BAND, ast.BitOr: IROp.BOR,
                ast.BitXor: IROp.BXOR, ast.LShift: IROp.LSHIFT, ast.RShift: IROp.RSHIFT,
            }
            ir_op = op_map.get(type(node.op), IROp.ADD)
            ctx.emit(ir_op, dst=_REG(result), src=[_REG(cur), rhs])
            ctx.emit(IROp.STORE_VAR, src=[_REG(result), _VAR(tgt_name)])
        else:
            # Fallback for subscript/attr augassign - treat as assign
            rhs = self._expr(node.value)
            self._assign_target(node.target, rhs)

    def visit_Expr(self, node: ast.Expr):
        self._expr(node.value)   # side-effect; result discarded

    def visit_If(self, node: ast.If):
        ctx = self._ctx
        cond = self._expr(node.test)
        cond_reg = ctx.temp()
        ctx.emit(IROp.STORE_VAR, src=[cond, _VAR(cond_reg)])

        true_blk  = ctx.new_block("if_true")
        false_blk = ctx.new_block("if_false")
        merge_blk = ctx.new_block("if_merge")

        ctx.emit_branch(cond_reg, true_blk, false_blk)

        # True branch
        ctx.switch(true_blk)
        for s in node.body:
            self.visit(s)
        if not ctx.block.is_terminated():
            ctx.emit_jump(merge_blk)

        # False branch
        ctx.switch(false_blk)
        for s in node.orelse:
            self.visit(s)
        if not ctx.block.is_terminated():
            ctx.emit_jump(merge_blk)

        ctx.switch(merge_blk)

    def visit_While(self, node: ast.While):
        ctx = self._ctx
        cond_blk  = ctx.new_block("while_cond")
        body_blk  = ctx.new_block("while_body")
        exit_blk  = ctx.new_block("while_exit")

        ctx.emit_jump(cond_blk)
        ctx.switch(cond_blk)

        cond     = self._expr(node.test)
        cond_reg = ctx.temp()
        ctx.emit(IROp.STORE_VAR, src=[cond, _VAR(cond_reg)])
        ctx.emit_branch(cond_reg, body_blk, exit_blk)

        ctx.switch(body_blk)
        self._loop_exits.append(exit_blk)
        for s in node.body:
            self.visit(s)
        self._loop_exits.pop()

        if not ctx.block.is_terminated():
            ctx.emit_jump(cond_blk)

        ctx.switch(exit_blk)

    def visit_For(self, node: ast.For):
        ctx     = self._ctx
        iter_op = self._expr(node.iter)
        it_reg  = ctx.temp()
        ctx.emit(IROp.GET_ITER, dst=_REG(it_reg), src=[iter_op])

        loop_blk  = ctx.new_block("for_loop")
        body_blk  = ctx.new_block("for_body")
        exit_blk  = ctx.new_block("for_exit")

        ctx.emit_jump(loop_blk)
        ctx.switch(loop_blk)

        next_reg = ctx.temp()
        ctx.emit(IROp.FOR_ITER, dst=_REG(next_reg),
                 src=[_REG(it_reg)], label=exit_blk.label)
        loop_blk.successors.extend([body_blk.id, exit_blk.id])
        body_blk.predecessors.append(loop_blk.id)
        exit_blk.predecessors.append(loop_blk.id)

        ctx.switch(body_blk)
        self._assign_target(node.target, _REG(next_reg))

        self._loop_exits.append(exit_blk)
        for s in node.body:
            self.visit(s)
        self._loop_exits.pop()

        if not ctx.block.is_terminated():
            ctx.emit_jump(loop_blk)

        ctx.switch(exit_blk)

    def visit_Break(self, node: ast.Break):
        if self._loop_exits:
            self._ctx.emit_jump(self._loop_exits[-1])

    def visit_Global(self, node: ast.Global):
        for name in node.names:
            self._ctx.emit(IROp.GLOBAL_DECL, src=[_VAR(name)])

    def visit_Delete(self, node: ast.Delete):
        for t in node.targets:
            op = self._expr(t)
            self._ctx.emit(IROp.DELETE, src=[op])

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self._ctx.emit(IROp.IMPORT, dst=_VAR(name),
                           src=[_CONST(alias.name)])

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            name = alias.asname or alias.name
            self._ctx.emit(IROp.IMPORT_FROM, dst=_VAR(name),
                           src=[_CONST(node.module), _CONST(alias.name)])

    def visit_Assert(self, node: ast.Assert):
        cond = self._expr(node.test)
        self._ctx.emit(IROp.ASSERT, src=[cond])

    def visit_Raise(self, node: ast.Raise):
        src = [self._expr(node.exc)] if node.exc else []
        self._ctx.emit(IROp.RAISE, src=src)

    def visit_Pass(self, node):
        self._ctx.emit(IROp.NOP)

    # ─────────────────────────────────────────────────────────────────────────
    # Expressions → emit instructions, return IROperand for result
    # ─────────────────────────────────────────────────────────────────────────
    def _expr(self, node: ast.expr) -> IROperand:
        method = f"_expr_{type(node).__name__}"
        handler = getattr(self, method, self._expr_fallback)
        return handler(node)

    def _expr_fallback(self, node):
        # Unknown node: emit NOP, return const None
        self._ctx.emit(IROp.NOP, metadata={"unknown_node": ast.dump(node)[:60]})
        return _CONST(None)

    def _expr_Constant(self, node: ast.Constant) -> IROperand:
        v = node.value
        if isinstance(v, str):
            idx = self._module.intern_string(v)
            tmp = self._ctx.temp()
            self._ctx.emit(IROp.LOAD_CONST, dst=_REG(tmp), src=[_STR(idx)])
            return _REG(tmp)
        else:
            idx = self._module.intern_const(v)
            tmp = self._ctx.temp()
            self._ctx.emit(IROp.LOAD_CONST, dst=_REG(tmp), src=[_CREF(idx)])
            return _REG(tmp)

    def _expr_Name(self, node: ast.Name) -> IROperand:
        tmp = self._ctx.temp()
        self._ctx.emit(IROp.LOAD_VAR, dst=_REG(tmp), src=[_VAR(node.id)])
        return _REG(tmp)

    _BINOP_MAP = {
        ast.Add:      IROp.ADD,
        ast.Sub:      IROp.SUB,
        ast.Mult:     IROp.MUL,
        ast.Div:      IROp.DIV,
        ast.FloorDiv: IROp.FLOORDIV,
        ast.Mod:      IROp.MOD,
        ast.Pow:      IROp.POW,
        ast.BitAnd:   IROp.BAND,
        ast.BitOr:    IROp.BOR,
        ast.BitXor:   IROp.BXOR,
        ast.LShift:   IROp.LSHIFT,
        ast.RShift:   IROp.RSHIFT,
    }

    def _expr_BinOp(self, node: ast.BinOp) -> IROperand:
        lop = self._expr(node.left)
        rop = self._expr(node.right)
        ir_op = self._BINOP_MAP.get(type(node.op), IROp.ADD)
        tmp = self._ctx.temp()
        self._ctx.emit(ir_op, dst=_REG(tmp), src=[lop, rop])
        return _REG(tmp)

    _UNOP_MAP = {
        ast.USub: IROp.NEG,
        ast.Not:  IROp.NOT,
        ast.Invert: IROp.BNOT,
    }

    def _expr_UnaryOp(self, node: ast.UnaryOp) -> IROperand:
        operand = self._expr(node.operand)
        ir_op   = self._UNOP_MAP.get(type(node.op), IROp.NEG)
        tmp     = self._ctx.temp()
        self._ctx.emit(ir_op, dst=_REG(tmp), src=[operand])
        return _REG(tmp)

    _CMPOP_MAP = {
        ast.Eq:    IROp.CMP_EQ,
        ast.NotEq: IROp.CMP_NE,
        ast.Lt:    IROp.CMP_LT,
        ast.LtE:   IROp.CMP_LE,
        ast.Gt:    IROp.CMP_GT,
        ast.GtE:   IROp.CMP_GE,
        ast.Is:    IROp.CMP_IS,
        ast.In:    IROp.CMP_IN,
    }

    def _expr_Compare(self, node: ast.Compare) -> IROperand:
        lop = self._expr(node.left)
        tmp = self._ctx.temp()
        for op, comp in zip(node.ops, node.comparators):
            rop   = self._expr(comp)
            ir_op = self._CMPOP_MAP.get(type(op), IROp.CMP_EQ)
            self._ctx.emit(ir_op, dst=_REG(tmp), src=[lop, rop])
            lop = _REG(tmp)
        return _REG(tmp)

    def _expr_Call(self, node: ast.Call) -> IROperand:
        func_op  = self._expr(node.func)
        arg_ops  = [self._expr(a) for a in node.args]
        tmp      = self._ctx.temp()
        self._ctx.emit(IROp.CALL, dst=_REG(tmp),
                       src=[func_op] + arg_ops,
                       metadata={"nargs": len(arg_ops)})
        return _REG(tmp)

    def _expr_Attribute(self, node: ast.Attribute) -> IROperand:
        obj = self._expr(node.value)
        tmp = self._ctx.temp()
        self._ctx.emit(IROp.LOAD_ATTR, dst=_REG(tmp),
                       src=[obj, IROperand("attr", node.attr)])
        return _REG(tmp)

    def _expr_Subscript(self, node: ast.Subscript) -> IROperand:
        obj = self._expr(node.value)
        idx = self._expr(node.slice)
        tmp = self._ctx.temp()
        self._ctx.emit(IROp.LOAD_INDEX, dst=_REG(tmp), src=[obj, idx])
        return _REG(tmp)

    def _expr_List(self, node: ast.List) -> IROperand:
        elts = [self._expr(e) for e in node.elts]
        tmp  = self._ctx.temp()
        self._ctx.emit(IROp.BUILD_LIST, dst=_REG(tmp),
                       src=elts + [_CNT(len(elts))])
        return _REG(tmp)

    def _expr_Tuple(self, node: ast.Tuple) -> IROperand:
        elts = [self._expr(e) for e in node.elts]
        tmp  = self._ctx.temp()
        self._ctx.emit(IROp.BUILD_TUPLE, dst=_REG(tmp),
                       src=elts + [_CNT(len(elts))])
        return _REG(tmp)

    def _expr_Dict(self, node: ast.Dict) -> IROperand:
        pairs = []
        for k, v in zip(node.keys, node.values):
            pairs.append(self._expr(k))
            pairs.append(self._expr(v))
        tmp = self._ctx.temp()
        self._ctx.emit(IROp.BUILD_DICT, dst=_REG(tmp),
                       src=pairs + [_CNT(len(node.keys))])
        return _REG(tmp)

    def _expr_IfExp(self, node: ast.IfExp) -> IROperand:
        """Ternary expression: body if test else orelse"""
        ctx = self._ctx
        cond     = self._expr(node.test)
        cond_reg = ctx.temp()
        ctx.emit(IROp.STORE_VAR, src=[cond, _VAR(cond_reg)])

        true_blk  = ctx.new_block("tern_true")
        false_blk = ctx.new_block("tern_false")
        merge_blk = ctx.new_block("tern_merge")
        res_reg   = ctx.temp()

        ctx.emit_branch(cond_reg, true_blk, false_blk)

        ctx.switch(true_blk)
        tv = self._expr(node.body)
        ctx.emit(IROp.STORE_VAR, src=[tv, _VAR(res_reg)])
        if not ctx.block.is_terminated():
            ctx.emit_jump(merge_blk)

        ctx.switch(false_blk)
        fv = self._expr(node.orelse)
        ctx.emit(IROp.STORE_VAR, src=[fv, _VAR(res_reg)])
        if not ctx.block.is_terminated():
            ctx.emit_jump(merge_blk)

        ctx.switch(merge_blk)
        out = ctx.temp()
        ctx.emit(IROp.LOAD_VAR, dst=_REG(out), src=[_VAR(res_reg)])
        return _REG(out)

    def _expr_JoinedStr(self, node: ast.JoinedStr) -> IROperand:
        """f-string: build via format"""
        ctx = self._ctx
        parts = []
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                parts.append(self._expr(val.value))
            elif isinstance(val, ast.Constant):
                # Use intern_string so it goes into string_table (like other string literals)
                tmp = ctx.temp()
                idx = self._module.intern_string(str(val.value))
                ctx.emit(IROp.LOAD_CONST, dst=_REG(tmp), src=[IROperand("str_ref", idx)])
                parts.append(_REG(tmp))
        if not parts:
            tmp = ctx.temp()
            idx = self._module.intern_const("")
            ctx.emit(IROp.LOAD_CONST, dst=_REG(tmp), src=[IROperand("str_ref", idx)])
            return _REG(tmp)
        # Join: use str() + str() chains
        result = parts[0]
        str_fn = ctx.temp()
        ctx.emit(IROp.LOAD_VAR, dst=_REG(str_fn), src=[_VAR("str")])
        # Convert result to str
        r0 = ctx.temp()
        ctx.emit(IROp.CALL, dst=_REG(r0), src=[_REG(str_fn), result])
        result = _REG(r0)
        for part in parts[1:]:
            rp = ctx.temp()
            ctx.emit(IROp.CALL, dst=_REG(rp), src=[_REG(str_fn), part])
            radd = ctx.temp()
            ctx.emit(IROp.ADD, dst=_REG(radd), src=[result, _REG(rp)])
            result = _REG(radd)
        return result

    def _expr_ListComp(self, node: ast.ListComp) -> IROperand:
        """[expr for target in iter if cond ...]"""
        ctx = self._ctx
        result_reg = ctx.temp()
        ctx.emit(IROp.BUILD_LIST, dst=_REG(result_reg),
                 src=[IROperand("count", 0)])

        for gen in node.generators:
            iter_op = self._expr(gen.iter)
            it_reg  = ctx.temp()
            ctx.emit(IROp.GET_ITER, dst=_REG(it_reg), src=[iter_op])

            loop_blk = ctx.new_block("lc_loop")
            body_blk = ctx.new_block("lc_body")
            exit_blk = ctx.new_block("lc_exit")

            ctx.emit_jump(loop_blk)
            ctx.switch(loop_blk)

            next_reg = ctx.temp()
            ctx.emit(IROp.FOR_ITER, dst=_REG(next_reg),
                     src=[_REG(it_reg)], label=exit_blk.label)

            ctx.switch(body_blk)
            self._assign_target(gen.target, _REG(next_reg))

            # Apply filters
            for if_cond in gen.ifs:
                cond  = self._expr(if_cond)
                cr    = ctx.temp()
                ctx.emit(IROp.STORE_VAR, src=[cond, _VAR(cr)])
                skip_blk = ctx.new_block("lc_skip")
                ctx.emit(IROp.JUMP_IF_FALSE, src=[_REG(cr)], label=skip_blk.label)
                # fallthrough to append

            # Append elt
            elt_op  = self._expr(node.elt)
            app_reg = ctx.temp()
            ctx.emit(IROp.LOAD_ATTR, dst=_REG(app_reg),
                     src=[_REG(result_reg), IROperand("attr", "append")])
            call_r  = ctx.temp()
            ctx.emit(IROp.CALL, dst=_REG(call_r), src=[_REG(app_reg), elt_op])

            if gen.ifs:
                ctx.switch(skip_blk)

            if not ctx.block.is_terminated():
                ctx.emit_jump(loop_blk)
            ctx.switch(exit_blk)

        return _REG(result_reg)

    def _expr_SetComp(self, node: ast.SetComp) -> IROperand:
        """Fallback: just return empty set"""
        ctx = self._ctx; r = ctx.temp()
        ctx.emit(IROp.NOP)
        # TODO: proper set comp - for now build as list and convert
        return _REG(r)

    def _expr_DictComp(self, node: ast.DictComp) -> IROperand:
        """Fallback: return empty dict"""
        ctx = self._ctx; r = ctx.temp()
        ctx.emit(IROp.BUILD_DICT, dst=_REG(r), src=[IROperand("count", 0)])
        return _REG(r)

    def _expr_BoolOp(self, node: ast.BoolOp) -> IROperand:
        ir_op = IROp.AND if isinstance(node.op, ast.And) else IROp.OR
        result = self._expr(node.values[0])
        for val in node.values[1:]:
            right = self._expr(val)
            tmp   = self._ctx.temp()
            self._ctx.emit(ir_op, dst=_REG(tmp), src=[result, right])
            result = _REG(tmp)
        return result

    # ── Target assignment helper ──────────────────────────────────────────────
    def _assign_target(self, target: ast.expr, src_op: IROperand):
        if isinstance(target, ast.Name):
            self._ctx.emit(IROp.STORE_VAR, src=[src_op, _VAR(target.id)])
        elif isinstance(target, ast.Attribute):
            obj = self._expr(target.value)
            self._ctx.emit(IROp.STORE_ATTR,
                           src=[obj, src_op, IROperand("attr", target.attr)])
        elif isinstance(target, ast.Subscript):
            obj = self._expr(target.value)
            idx = self._expr(target.slice)
            self._ctx.emit(IROp.STORE_INDEX, src=[obj, idx, src_op])
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Unpack: emit LOAD_INDEX per element
            for i, elt in enumerate(target.elts):
                idx = self._module.intern_const(i)
                tmp = self._ctx.temp()
                self._ctx.emit(IROp.LOAD_INDEX, dst=_REG(tmp),
                               src=[src_op, _CREF(idx)])
                self._assign_target(elt, _REG(tmp))
