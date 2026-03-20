"""
vm/compiler.py
==============
Compiles Python source → Pyrph VM Bytecode.

Supported:
- All expressions: constants, names, binop, unary, compare, boolop,
  call, attribute, subscript, list/dict/tuple/set, f-strings, ternary
- Statements: assign, augassign, if/elif/else, for, while,
  break/continue, def, class (via EXEC fallback), return,
  import/from-import, delete, pass, try/except, raise, assert
- Nested functions + basic closures via frame stack
- For-loop vars optionally stored in registers (hybrid)

Unsupported constructs fall back to an EXEC instruction,
which passes them to the host Python interpreter.
"""
from __future__ import annotations
import ast
import struct
from typing import Optional, List
from .opcodes import OpcodeMap, Bytecode, INSTRUCTION_DEFS


class _Label:
    def __init__(self, name: str):
        self.name = name
    def __repr__(self):
        return f"<Label {self.name}>"


class _Compiler:
    """One scope (module or function)."""

    MAX_REGS   = 8
    REG_THRESH = 3   # use register if var assigned ≥ this many times in a loop

    def __init__(self, om: OpcodeMap, arg_names: List[str] = None,
                 use_regs: bool = True):
        self.om        = om
        self.arg_names = arg_names or []
        self.use_regs  = use_regs
        self._stream:  list = []   # (opcode_byte, *arg_bytes) or _Label
        self.constants: list  = []
        self.names:     list  = []
        self._lc = 0
        self._label_pos: dict = {}
        self._patches:   list = []   # (stream_idx_of_placeholder, label)
        self._loop_stack: list = []  # (continue_label, break_label)
        self._reg_map:    dict = {}
        self._reg_next = 0

    # ── public ────────────────────────────────────────────────────────────

    def compile_module(self, tree: ast.Module) -> Bytecode:
        self._scan_regs(tree.body)
        for node in tree.body:
            self._stmt(node)
        self._emit0("HALT")
        return self._finish([])

    def compile_func(self, body: List[ast.stmt]) -> Bytecode:
        for name in self.arg_names:
            idx = self._name(name)
            self._emit1("STORE_NAME", idx)
        self._scan_regs(body)
        for node in body:
            self._stmt(node)
        self._emit0("LOAD_CONST", self._const(None))
        self._emit0("RETURN")
        return self._finish(self.arg_names)

    # ── label / patch ─────────────────────────────────────────────────────

    def _new_label(self) -> _Label:
        self._lc += 1
        return _Label(f"L{self._lc}")

    def _mark(self, label: _Label):
        self._label_pos[label.name] = len(self._stream)

    def _patch_jumps(self, raw: bytearray, stream_map: List[int]):
        """Fill in 2-byte jump targets."""
        for (sidx, label) in self._patches:
            target_sidx = self._label_pos[label.name]
            target_byte = stream_map[target_sidx] if target_sidx < len(stream_map) else len(raw)
            struct.pack_into(">H", raw, stream_map[sidx] + 1, target_byte)

    # ── emit ──────────────────────────────────────────────────────────────

    def _emit0(self, name: str, arg: int = None):
        byte = self.om[name]
        if arg is None:
            self._stream.append((byte,))
        else:
            self._stream.append((byte, arg))

    def _emit1(self, name: str, a: int):
        self._stream.append((self.om[name], a))

    def _emit2(self, name: str, label: _Label):
        sidx = len(self._stream)
        self._stream.append((self.om[name], 0, 0))  # placeholder
        self._patches.append((sidx, label))

    def _emit3(self, name: str, a: int, b: int):
        self._stream.append((self.om[name], a, b))

    # ── pool helpers ──────────────────────────────────────────────────────

    def _const(self, v) -> int:
        try:
            return self.constants.index(v)
        except ValueError:
            self.constants.append(v)
            return len(self.constants) - 1

    def _name(self, s: str) -> int:
        try:
            return self.names.index(s)
        except ValueError:
            self.names.append(s)
            return len(self.names) - 1

    # ── register allocator ────────────────────────────────────────────────

    def _scan_regs(self, stmts: list):
        """Assign registers to frequently-assigned names in for-loops."""
        if not self.use_regs:
            return
        import collections
        counts: dict = collections.Counter()
        for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    counts[node.target.id] += 3
            elif isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = (node.targets if isinstance(node, ast.Assign)
                           else [node.target])
                for t in targets:
                    if isinstance(t, ast.Name):
                        counts[t.id] += 1
        for name, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            if cnt >= self.REG_THRESH and self._reg_next < self.MAX_REGS:
                self._reg_map[name] = self._reg_next
                self._reg_next += 1

    def _load_name(self, name: str):
        if name in self._reg_map:
            self._emit1("REG_LOAD", self._reg_map[name])
        else:
            self._emit1("LOAD_NAME", self._name(name))

    def _store_name(self, name: str):
        if name in self._reg_map:
            self._emit1("REG_STORE", self._reg_map[name])
        else:
            self._emit1("STORE_NAME", self._name(name))

    # ── finish ────────────────────────────────────────────────────────────

    def _finish(self, arg_names: list) -> Bytecode:
        raw       = bytearray()
        stream_map: List[int] = []   # stream_idx → byte_offset
        for item in self._stream:
            if isinstance(item, _Label):
                self._label_pos[item.name] = len(raw)
                continue
            stream_map.append(len(raw))
            for b in item:
                raw.append(b & 0xFF)
        stream_map.append(len(raw))   # sentinel
        self._patch_jumps(raw, stream_map)
        return Bytecode(
            instructions=bytes(raw),
            constants=self.constants,
            names=self.names,
            arg_names=arg_names,
            opcode_map=self.om,
        )

    # ── expressions ──────────────────────────────────────────────────────

    def _expr(self, node: ast.expr):
        t = type(node)

        if t is ast.Constant:
            self._emit1("LOAD_CONST", self._const(node.value))

        elif t is ast.Name:
            self._load_name(node.id)

        elif t is ast.BinOp:
            self._expr(node.left)
            self._expr(node.right)
            op_map = {
                ast.Add: "ADD", ast.Sub: "SUB", ast.Mult: "MUL",
                ast.Div: "DIV", ast.FloorDiv: "FLOORDIV",
                ast.Mod: "MOD", ast.Pow: "POW",
                ast.BitAnd: "BAND", ast.BitOr: "BOR", ast.BitXor: "BXOR",
                ast.LShift: "BSHL", ast.RShift: "BSHR",
            }
            self._emit0(op_map[type(node.op)])

        elif t is ast.UnaryOp:
            self._expr(node.operand)
            op_map = {ast.USub:"NEG", ast.UAdd:"POS",
                      ast.Invert:"BINV", ast.Not:"NOT"}
            self._emit0(op_map[type(node.op)])

        elif t is ast.Compare:
            self._expr(node.left)
            for op, cmp in zip(node.ops, node.comparators):
                self._expr(cmp)
                op_map = {
                    ast.Eq:"CMP_EQ", ast.NotEq:"CMP_NE",
                    ast.Lt:"CMP_LT", ast.LtE:"CMP_LE",
                    ast.Gt:"CMP_GT", ast.GtE:"CMP_GE",
                    ast.In:"CMP_IN", ast.NotIn:"CMP_NOT_IN",
                    ast.Is:"CMP_IS", ast.IsNot:"CMP_IS_NOT",
                }
                self._emit0(op_map[type(op)])
                if len(node.ops) > 1:
                    # chained compare: DUP result, ROT, AND
                    pass  # simplified: just handle common single-cmp case

        elif t is ast.BoolOp:
            end = self._new_label()
            for i, val in enumerate(node.values):
                self._expr(val)
                if i < len(node.values) - 1:
                    if isinstance(node.op, ast.And):
                        self._emit2("JMP_FALSE_PEEK", end)
                    else:
                        self._emit2("JMP_TRUE_PEEK", end)
                    self._emit0("POP")
            self._mark(end)

        elif t is ast.IfExp:
            else_lbl = self._new_label()
            end_lbl  = self._new_label()
            self._expr(node.test)
            self._emit2("JMP_FALSE", else_lbl)
            self._expr(node.body)
            self._emit2("JMP", end_lbl)
            self._mark(else_lbl)
            self._expr(node.orelse)
            self._mark(end_lbl)

        elif t is ast.Call:
            self._expr(node.func)
            for arg in node.args:
                self._expr(arg)
            if not node.keywords:
                self._emit1("CALL", len(node.args))
            else:
                for kw in node.keywords:
                    self._emit1("LOAD_CONST", self._const(kw.arg))
                    self._expr(kw.value)
                self._emit3("CALL_KW", len(node.args), len(node.keywords))

        elif t is ast.Attribute:
            self._expr(node.value)
            self._emit1("GET_ATTR", self._name(node.attr))

        elif t is ast.Subscript:
            self._expr(node.value)
            if isinstance(node.slice, ast.Slice):
                lo = node.slice.lower
                hi = node.slice.upper
                self._expr(lo if lo else ast.Constant(value=None))
                self._expr(hi if hi else ast.Constant(value=None))
                self._emit0("SLICE")
            else:
                self._expr(node.slice)
                self._emit0("GET_ITEM")

        elif t is ast.List:
            for elt in node.elts:
                self._expr(elt)
            self._emit1("BUILD_LIST", len(node.elts))

        elif t is ast.Tuple:
            for elt in node.elts:
                self._expr(elt)
            self._emit1("BUILD_TUPLE", len(node.elts))

        elif t is ast.Dict:
            for k, v in zip(node.keys, node.values):
                self._expr(k)
                self._expr(v)
            self._emit1("BUILD_DICT", len(node.keys))

        elif t is ast.Set:
            for elt in node.elts:
                self._expr(elt)
            self._emit1("BUILD_SET", len(node.elts))

        elif t is ast.JoinedStr:
            # f-string: compile each part
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    self._expr(v)
                    parts.append(v)
                elif isinstance(v, ast.FormattedValue):
                    self._expr(v.value)
                    self._emit0("FORMAT_VAL")
                    parts.append(v)
            self._emit1("BUILD_STR", len(node.values))

        elif t is ast.Lambda:
            # compile as nested func with single return
            inner_args = [a.arg for a in node.args.args]
            sub_comp   = _Compiler(self.om, arg_names=inner_args,
                                   use_regs=self.use_regs)
            ret_body   = [ast.Return(value=node.body)]
            sub_bc     = sub_comp.compile_func(ret_body)
            self._emit1("MAKE_FUNC", self._const(_bc_to_spec(sub_bc)))

        else:
            # Fallback: unparse and use EXEC/EVAL
            try:
                src = ast.unparse(node)
                self._emit1("LOAD_CONST", self._const(src))
                self._emit0("FORMAT_VAL")   # placeholder — codegen will EVAL
            except Exception:
                self._emit1("LOAD_CONST", self._const(None))

    # ── statements ────────────────────────────────────────────────────────

    def _stmt(self, node: ast.stmt):
        t = type(node)

        if t is ast.Expr:
            self._expr(node.value)
            self._emit0("POP")

        elif t is ast.Assign:
            self._expr(node.value)
            if len(node.targets) == 1:
                self._assign_target(node.targets[0])
            else:
                for tgt in node.targets:
                    self._emit0("DUP")
                    self._assign_target(tgt)
                self._emit0("POP")

        elif t is ast.AugAssign:
            self._load_target(node.target)
            self._expr(node.value)
            op_map = {
                ast.Add:"ADD", ast.Sub:"SUB", ast.Mult:"MUL",
                ast.Div:"DIV", ast.FloorDiv:"FLOORDIV",
                ast.Mod:"MOD", ast.Pow:"POW",
                ast.BitAnd:"BAND", ast.BitOr:"BOR", ast.BitXor:"BXOR",
                ast.LShift:"BSHL", ast.RShift:"BSHR",
            }
            self._emit0(op_map[type(node.op)])
            self._assign_target(node.target)

        elif t is ast.AnnAssign:
            if node.value:
                self._expr(node.value)
                self._assign_target(node.target)

        elif t is ast.Delete:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self._emit1("DEL_NAME", self._name(tgt.id))
                elif isinstance(tgt, ast.Attribute):
                    self._expr(tgt.value)
                    self._emit1("DEL_ATTR", self._name(tgt.attr))
                elif isinstance(tgt, ast.Subscript):
                    self._expr(tgt.value)
                    self._expr(tgt.slice)
                    self._emit0("DEL_ITEM")

        elif t is ast.Pass:
            pass  # nothing

        elif t is ast.If:
            else_lbl = self._new_label()
            end_lbl  = self._new_label()
            self._expr(node.test)
            self._emit2("JMP_FALSE", else_lbl)
            for s in node.body:
                self._stmt(s)
            if node.orelse:
                self._emit2("JMP", end_lbl)
            self._mark(else_lbl)
            for s in (node.orelse or []):
                self._stmt(s)
            self._mark(end_lbl)

        elif t is ast.While:
            top  = self._new_label()
            end  = self._new_label()
            self._loop_stack.append((top, end))
            self._mark(top)
            self._expr(node.test)
            self._emit2("JMP_FALSE", end)
            for s in node.body:
                self._stmt(s)
            self._emit2("JMP", top)
            self._mark(end)
            for s in (node.orelse or []):
                self._stmt(s)
            self._loop_stack.pop()

        elif t is ast.For:
            end  = self._new_label()
            top  = self._new_label()
            self._expr(node.iter)
            self._emit0("GET_ITER")
            self._loop_stack.append((top, end))
            self._mark(top)
            self._emit2("FOR_ITER", end)
            # assign loop var
            if isinstance(node.target, ast.Name):
                self._store_name(node.target.id)
            elif isinstance(node.target, (ast.Tuple, ast.List)):
                self._emit1("UNPACK", len(node.target.elts))
                for elt in reversed(node.target.elts):
                    if isinstance(elt, ast.Name):
                        self._store_name(elt.id)
            for s in node.body:
                self._stmt(s)
            self._emit2("JMP", top)
            self._mark(end)
            for s in (node.orelse or []):
                self._stmt(s)
            self._loop_stack.pop()

        elif t is ast.Break:
            if self._loop_stack:
                self._emit2("JMP", self._loop_stack[-1][1])

        elif t is ast.Continue:
            if self._loop_stack:
                self._emit2("JMP", self._loop_stack[-1][0])

        elif t is ast.Return:
            if node.value:
                self._expr(node.value)
            else:
                self._emit1("LOAD_CONST", self._const(None))
            self._emit0("RETURN")

        elif t is ast.Raise:
            if node.exc:
                self._expr(node.exc)
            else:
                self._emit1("LOAD_CONST", self._const(None))
            self._emit0("RAISE")

        elif t is ast.Assert:
            end = self._new_label()
            self._expr(node.test)
            self._emit2("JMP_TRUE", end)
            if node.msg:
                self._expr(node.msg)
            else:
                self._emit1("LOAD_CONST", self._const("AssertionError"))
            self._emit0("RAISE")
            self._mark(end)

        elif t is ast.Try:
            handler_lbl = self._new_label()
            end_lbl     = self._new_label()
            self._emit2("SETUP_TRY", handler_lbl)
            for s in node.body:
                self._stmt(s)
            self._emit0("POP_TRY")
            self._emit2("JMP", end_lbl)
            self._mark(handler_lbl)
            # simplified: run first handler body (full dispatch in codegen)
            for h in node.handlers:
                for s in h.body:
                    self._stmt(s)
                break
            self._mark(end_lbl)
            for s in (node.finalbody if hasattr(node,'finalbody') else []):
                self._stmt(s)

        elif t is ast.FunctionDef or t is ast.AsyncFunctionDef:
            args     = [a.arg for a in node.args.args]
            sub_comp = _Compiler(self.om, arg_names=args,
                                 use_regs=self.use_regs)
            sub_bc   = sub_comp.compile_func(node.body)
            spec_idx = self._const(_bc_to_spec(sub_bc))
            self._emit1("MAKE_FUNC", spec_idx)
            self._store_name(node.name)

        elif t is ast.Import:
            for alias in node.names:
                self._emit1("IMPORT", self._name(alias.name))
                local = alias.asname or alias.name.split(".")[0]
                self._store_name(local)

        elif t is ast.ImportFrom:
            mod   = node.module or ""
            for alias in node.names:
                m_idx = self._name(mod)
                a_idx = self._name(alias.name)
                self._emit3("IMPORT_FROM", m_idx, a_idx)
                local = alias.asname or alias.name
                self._store_name(local)

        elif t is ast.Global or t is ast.Nonlocal:
            pass  # handled at runtime via frame lookup

        elif t is ast.ClassDef:
            # Fallback: compile class body as EXEC
            src = ast.unparse(node)
            self._emit1("LOAD_CONST", self._const(src))
            # codegen will emit an exec() call for this constant
            self._emit0("POP")

        elif t is ast.With:
            # Simplified: run body directly (no context manager protocol in VM)
            for s in node.body:
                self._stmt(s)

        else:
            # Unknown node: unparse and exec
            try:
                src = ast.unparse(node)
                self._emit1("LOAD_CONST", self._const(src))
                self._emit0("POP")
            except Exception:
                pass

    # ── assignment targets ────────────────────────────────────────────────

    def _assign_target(self, tgt: ast.expr):
        if isinstance(tgt, ast.Name):
            self._store_name(tgt.id)
        elif isinstance(tgt, ast.Attribute):
            self._expr(tgt.value)
            self._emit1("SET_ATTR", self._name(tgt.attr))
        elif isinstance(tgt, ast.Subscript):
            self._expr(tgt.value)
            self._expr(tgt.slice)
            self._emit0("SET_ITEM")
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            self._emit1("UNPACK", len(tgt.elts))
            for elt in reversed(tgt.elts):
                self._assign_target(elt)

    def _load_target(self, tgt: ast.expr):
        if isinstance(tgt, ast.Name):
            self._load_name(tgt.id)
        elif isinstance(tgt, ast.Attribute):
            self._expr(tgt.value)
            self._emit1("GET_ATTR", self._name(tgt.attr))
        elif isinstance(tgt, ast.Subscript):
            self._expr(tgt.value)
            self._expr(tgt.slice)
            self._emit0("GET_ITEM")


# ── helper ────────────────────────────────────────────────────────────────

def _bc_to_spec(bc: Bytecode) -> list:
    """
    Serialise a Bytecode to a spec list stored in the parent const pool.
    spec = [instructions_bytes, arg_names, opmap_translation_bytes,
             constants_spec, names_list]
    Constants that are Bytecode objects are recursively converted to specs.
    """
    consts_ser = [
        _bc_to_spec(c) if isinstance(c, Bytecode) else c
        for c in bc.constants
    ]
    return [
        bc.instructions,
        bc.arg_names,
        bc.opcode_map.to_translation_table(),
        consts_ser,
        bc.names,
    ]


# ── public API ────────────────────────────────────────────────────────────

def compile_source(source: str,
                   opcode_map: Optional[OpcodeMap] = None,
                   use_regs: bool = True) -> Bytecode:
    """
    Compile Python source string to Pyrph VM Bytecode.

    Parameters
    ----------
    source     : Python source code
    opcode_map : OpcodeMap to use (fresh random map if None)
    use_regs   : enable hybrid register allocation

    Returns
    -------
    Bytecode object (use vm.encryptor to encrypt before embedding)
    """
    if opcode_map is None:
        opcode_map = OpcodeMap.generate()
    tree = ast.parse(source)
    comp = _Compiler(opcode_map, use_regs=use_regs)
    return comp.compile_module(tree)
