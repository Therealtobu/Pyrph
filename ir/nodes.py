"""
IR node definitions.
All computation is expressed as a flat list of IRInstruction objects
grouped into IRBlocks inside IRFunctions.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


# ── Opcode set ────────────────────────────────────────────────────────────────
class IROp(Enum):
    # Memory
    LOAD_CONST    = auto()
    LOAD_VAR      = auto()
    STORE_VAR     = auto()
    LOAD_ATTR     = auto()
    STORE_ATTR    = auto()
    LOAD_INDEX    = auto()
    STORE_INDEX   = auto()

    # Arithmetic
    ADD           = auto()
    SUB           = auto()
    MUL           = auto()
    DIV           = auto()
    FLOORDIV      = auto()
    MOD           = auto()
    POW           = auto()
    NEG           = auto()

    # Bitwise
    BAND          = auto()
    BOR           = auto()
    BXOR          = auto()
    BNOT          = auto()
    LSHIFT        = auto()
    RSHIFT        = auto()

    # Logic
    AND           = auto()
    OR            = auto()
    NOT           = auto()

    # Comparison
    CMP_EQ        = auto()
    CMP_NE        = auto()
    CMP_LT        = auto()
    CMP_LE        = auto()
    CMP_GT        = auto()
    CMP_GE        = auto()
    CMP_IS        = auto()
    CMP_IN        = auto()

    # Control flow
    JUMP          = auto()
    JUMP_IF_TRUE  = auto()
    JUMP_IF_FALSE = auto()
    LABEL         = auto()

    # Functions
    CALL          = auto()
    RETURN        = auto()

    # Stack (explicit for VM)
    PUSH          = auto()
    POP           = auto()
    DUP           = auto()

    # Collections
    BUILD_LIST    = auto()
    BUILD_DICT    = auto()
    BUILD_TUPLE   = auto()

    # Iteration
    GET_ITER      = auto()
    FOR_ITER      = auto()

    # Exception
    RAISE         = auto()
    TRY_BEGIN     = auto()
    TRY_END       = auto()
    EXCEPT        = auto()

    # Special / meta
    NOP           = auto()
    FAKE          = auto()   # dead/junk instruction injected by IR-obf
    PHI           = auto()   # SSA φ-node (CFG merge point)
    DELETE        = auto()
    IMPORT        = auto()
    IMPORT_FROM   = auto()
    GLOBAL_DECL   = auto()
    ASSERT        = auto()


# ── Operand ───────────────────────────────────────────────────────────────────
@dataclass
class IROperand:
    """
    kind:
      'const'       – literal Python value
      'var'         – local variable name
      'reg'         – SSA register / temp  (__t1, __t2 …)
      'label'       – block label (jump target)
      'attr'        – attribute string
      'str_ref'     – index into IRModule.string_table
      'const_ref'   – index into IRModule.const_table
      'func_ref'    – function name
      'builtin'     – builtin name
      'count'       – integer count operand (BUILD_LIST n, etc.)
    """
    kind:  str
    value: Any

    def __repr__(self) -> str:
        return f"({self.kind}:{self.value!r})"


# ── Instruction ───────────────────────────────────────────────────────────────
@dataclass
class IRInstruction:
    op:       IROp
    dst:      Optional[IROperand]   = None
    src:      list[IROperand]       = field(default_factory=list)
    label:    Optional[str]         = None    # for LABEL / JUMP targets
    metadata: dict                  = field(default_factory=dict)

    # VM-phase fields (filled in by interleaver / encryptor)
    enc_op:   Optional[int]         = None    # encrypted opcode
    block_id: Optional[int]         = None    # owning IRBlock.id
    vm_slot:  Optional[int]         = None    # 0=VM1 part, 1=VM2 part, 2=VM3

    def __repr__(self) -> str:
        d = f" dst={self.dst}" if self.dst else ""
        s = f" src={self.src}" if self.src else ""
        lbl = f" @{self.label}" if self.label else ""
        return f"IR[{self.op.name}{d}{s}{lbl}]"


# ── Basic Block ───────────────────────────────────────────────────────────────
@dataclass
class IRBlock:
    id:            int
    label:         str
    instructions:  list[IRInstruction] = field(default_factory=list)
    predecessors:  list[int]           = field(default_factory=list)
    successors:    list[int]           = field(default_factory=list)
    encrypt_key:   Optional[int]       = None  # set by BlockEncryptor

    def emit(self, instr: IRInstruction):
        instr.block_id = self.id
        self.instructions.append(instr)

    def last_op(self) -> Optional[IROp]:
        return self.instructions[-1].op if self.instructions else None

    def is_terminated(self) -> bool:
        term = {IROp.JUMP, IROp.JUMP_IF_TRUE, IROp.JUMP_IF_FALSE, IROp.RETURN}
        return self.last_op() in term


# ── Function ──────────────────────────────────────────────────────────────────
@dataclass
class IRFunction:
    name:    str
    args:    list[str]
    blocks:  list[IRBlock] = field(default_factory=list)
    _temps:  int            = 0

    def new_temp(self) -> str:
        self._temps += 1
        return f"__t{self._temps}"

    def new_block(self, label: Optional[str] = None) -> IRBlock:
        bid   = len(self.blocks)
        lbl   = label or f"__bb{bid}"
        block = IRBlock(id=bid, label=lbl)
        self.blocks.append(block)
        return block

    def entry_block(self) -> IRBlock:
        return self.blocks[0]

    def all_instructions(self):
        for b in self.blocks:
            yield from b.instructions


# ── Module ────────────────────────────────────────────────────────────────────
@dataclass
class IRModule:
    functions:    list[IRFunction]    = field(default_factory=list)
    globals_init: list[IRInstruction] = field(default_factory=list)
    string_table: dict[str, int]      = field(default_factory=dict)
    const_table:  dict[int, Any]      = field(default_factory=dict)
    _str_ctr:     int                 = 0
    _const_ctr:   int                 = 0

    def intern_string(self, s: str) -> int:
        if s not in self.string_table:
            self.string_table[s] = self._str_ctr
            self.const_table[self._str_ctr] = s
            self._str_ctr += 1
        return self.string_table[s]

    def intern_const(self, v: Any) -> int:
        cid = self._const_ctr
        self._const_ctr += 1
        self.const_table[cid] = v
        return cid

    def get_function(self, name: str) -> Optional[IRFunction]:
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None
