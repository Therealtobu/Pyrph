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

    def visit_AugAssign(self, node: ast.Assign):
        # Normaliser should have removed these; handle as fallback
        self.visit_Assign(node)

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
