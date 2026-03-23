"""
VM opcode definitions for VM1, VM2, and VM3.

VM1 and VM2 share the same opcode *names* but have completely different
numeric IDs and execution semantics.  VM3 uses a merged opcode space
where a single opcode encodes parts from both VM1 and VM2.

Opcode naming convention:
  V  – VM instruction prefix
  R  – Register operand
  S  – Stack operand
  I  – Immediate (constant) operand
"""
from enum import IntEnum


class VM1Op(IntEnum):
    """
    VM1 – Stack+Register hybrid (inner / stronger VM).
    Uses even IDs to avoid collision with VM2.
    """
    NOP        = 0x00
    HALT       = 0x02
    # Stack ops
    SPUSH      = 0x04    # push register → stack
    SPOP       = 0x06    # pop stack → register
    SDUP       = 0x08    # duplicate top of stack
    SSWAP      = 0x0A    # swap top two stack items
    # Register ops
    RLOAD_CONST= 0x0C    # reg[dst] = const
    RLOAD_VAR  = 0x0E    # reg[dst] = env[name]
    RSTORE_VAR = 0x10    # env[name] = reg[src]
    RLOAD_IDX  = 0x12    # reg[dst] = reg[obj][reg[idx]]
    RSTORE_IDX = 0x14    # reg[obj][reg[idx]] = reg[src]
    RLOAD_ATTR = 0x16    # reg[dst] = getattr(reg[obj], name)
    RSTORE_ATTR= 0x18    # setattr(reg[obj], name, reg[src])
    # Arithmetic (register-based)
    RADD       = 0x1A
    RSUB       = 0x1C
    RMUL       = 0x1E
    RDIV       = 0x20
    RFLOOR     = 0x22
    RMOD       = 0x24
    RPOW       = 0x26
    RNEG       = 0x28
    # Bitwise
    RBAND      = 0x2A
    RBOR       = 0x2C
    RBXOR      = 0x2E
    RBNOT      = 0x30
    RLSHIFT    = 0x32
    RRSHIFT    = 0x34
    # Logic
    RAND       = 0x36
    ROR        = 0x38
    RNOT_L     = 0x3A
    # Compare
    RCEQ       = 0x3C
    RCNE       = 0x3E
    RCLT       = 0x40
    RCLE       = 0x42
    RCGT       = 0x44
    RCGE       = 0x46
    RCIS       = 0x48
    RCIN       = 0x4A
    # Control flow
    JMP        = 0x4C
    JMPT       = 0x4E    # jump if reg true
    JMPF       = 0x50    # jump if reg false
    # Functions
    CALL       = 0x52
    RET        = 0x54
    # Collections
    BLIST      = 0x56
    BDICT      = 0x58
    BTUPLE     = 0x5A
    # Iteration
    GETITER    = 0x5C
    FORITER    = 0x5E
    # Exception
    RAISE      = 0x60
    # Special
    IMPORT     = 0x62
    IMPORTFROM = 0x64
    DELETE     = 0x66
    GLOBAL     = 0x68
    TRY_ENTER  = 0x6A   # push exception handler label
    TRY_EXIT   = 0x6B   # pop exception handler


class VM2Op(IntEnum):
    """
    VM2 – Side VM (same paradigm, completely different logic / opcode IDs).
    Uses odd IDs.
    """
    NOP        = 0x01
    HALT       = 0x03
    # Stack ops
    WPUSH      = 0x05
    WPOP       = 0x07
    WDUP       = 0x09
    WSWAP      = 0x0B
    # Register ops  (registers named w0..w15 to distinguish from VM1 r0..r15)
    WLOAD_K    = 0x0D
    WLOAD_V    = 0x0F
    WSTORE_V   = 0x11
    WLOAD_I    = 0x13
    WSTORE_I   = 0x15
    WLOAD_A    = 0x17
    WSTORE_A   = 0x19
    # Arithmetic – different encoding order (dst is src[1] not src[0] in VM2)
    WADD       = 0x1B
    WSUB       = 0x1D
    WMUL       = 0x1F
    WDIV       = 0x21
    WFLOOR     = 0x23
    WMOD       = 0x25
    WPOW       = 0x27
    WNEG       = 0x29
    # Bitwise
    WBAND      = 0x2B
    WBOR       = 0x2D
    WBXOR      = 0x2F
    WBNOT      = 0x31
    WLSH       = 0x33
    WRSH       = 0x35
    # Logic
    WAND       = 0x37
    WOR        = 0x39
    WNOT       = 0x3B
    # Compare
    WCEQ       = 0x3D
    WCNE       = 0x3F
    WCLT       = 0x41
    WCLE       = 0x43
    WCGT       = 0x45
    WCGE       = 0x47
    WCIS       = 0x49
    WCIN       = 0x4B
    # Control flow
    WJMP       = 0x4D
    WJMPT      = 0x4F
    WJMPF      = 0x51
    # Functions
    WCALL      = 0x53
    WRET       = 0x55
    # Collections
    WBLIST     = 0x57
    WBDICT     = 0x59
    WBTUPLE    = 0x5B
    # Iteration
    WGETITER   = 0x5D
    WFORITER   = 0x5F
    # Exception
    WRAISE     = 0x61
    # Special
    WIMPORT    = 0x63
    WIMPORTFROM= 0x65
    WDELETE    = 0x67
    WGLOBAL    = 0x69
    WTRY_ENTER = 0x6C
    WTRY_EXIT  = 0x6D


# VM3 opcode space: merged IDs from VM1+VM2, remapped and shuffled
# The actual mapping is generated at codegen time (see codegen.py)
# so this file only defines the symbolic constants used in the runtime.
VM3_MAGIC = 0xAB_CD_EF_01   # identifies a VM3 bytecode stream

# IR opcode → (VM1Op, VM2Op) split table
# For each IR operation, define which sub-operation goes to VM1 and VM2
IR_TO_VM_SPLIT: dict[str, tuple] = {
    "ADD":       (VM1Op.RADD,    VM2Op.WADD),
    "SUB":       (VM1Op.RSUB,    VM2Op.WSUB),
    "MUL":       (VM1Op.RMUL,    VM2Op.WMUL),
    "DIV":       (VM1Op.RDIV,    VM2Op.WDIV),
    "FLOORDIV":  (VM1Op.RFLOOR,  VM2Op.WFLOOR),
    "MOD":       (VM1Op.RMOD,    VM2Op.WMOD),
    "POW":       (VM1Op.RPOW,    VM2Op.WPOW),
    "NEG":       (VM1Op.RNEG,    VM2Op.WNEG),
    "BAND":      (VM1Op.RBAND,   VM2Op.WBAND),
    "BOR":       (VM1Op.RBOR,    VM2Op.WBOR),
    "BXOR":      (VM1Op.RBXOR,   VM2Op.WBXOR),
    "BNOT":      (VM1Op.RBNOT,   VM2Op.WBNOT),
    "LSHIFT":    (VM1Op.RLSHIFT,  VM2Op.WLSH),
    "RSHIFT":    (VM1Op.RRSHIFT,  VM2Op.WRSH),
    "AND":       (VM1Op.RAND,    VM2Op.WAND),
    "OR":        (VM1Op.ROR,     VM2Op.WOR),
    "NOT":       (VM1Op.RNOT_L,  VM2Op.WNOT),
    "CMP_EQ":    (VM1Op.RCEQ,    VM2Op.WCEQ),
    "CMP_NE":    (VM1Op.RCNE,    VM2Op.WCNE),
    "CMP_LT":    (VM1Op.RCLT,    VM2Op.WCLT),
    "CMP_LE":    (VM1Op.RCLE,    VM2Op.WCLE),
    "CMP_GT":    (VM1Op.RCGT,    VM2Op.WCGT),
    "CMP_GE":    (VM1Op.RCGE,    VM2Op.WCGE),
    "CMP_IS":    (VM1Op.RCIS,    VM2Op.WCIS),
    "CMP_IN":    (VM1Op.RCIN,    VM2Op.WCIN),
    "LOAD_CONST":(VM1Op.RLOAD_CONST, VM2Op.WLOAD_K),
    "LOAD_VAR":  (VM1Op.RLOAD_VAR,   VM2Op.WLOAD_V),
    "STORE_VAR": (VM1Op.RSTORE_VAR,  VM2Op.WSTORE_V),
    "LOAD_ATTR": (VM1Op.RLOAD_ATTR,  VM2Op.WLOAD_A),
    "STORE_ATTR":(VM1Op.RSTORE_ATTR, VM2Op.WSTORE_A),
    "LOAD_INDEX":(VM1Op.RLOAD_IDX,   VM2Op.WLOAD_I),
    "STORE_INDEX":(VM1Op.RSTORE_IDX, VM2Op.WSTORE_I),
    "CALL":      (VM1Op.CALL,    VM2Op.WCALL),
    "RETURN":    (VM1Op.RET,     VM2Op.WRET),
    "JUMP":      (VM1Op.JMP,     VM2Op.WJMP),
    "JUMP_IF_TRUE":  (VM1Op.JMPT, VM2Op.WJMPT),
    "JUMP_IF_FALSE": (VM1Op.JMPF, VM2Op.WJMPF),
    "BUILD_LIST":    (VM1Op.BLIST,  VM2Op.WBLIST),
    "BUILD_DICT":    (VM1Op.BDICT,  VM2Op.WBDICT),
    "BUILD_TUPLE":   (VM1Op.BTUPLE, VM2Op.WBTUPLE),
    "GET_ITER":      (VM1Op.GETITER,VM2Op.WGETITER),
    "FOR_ITER":      (VM1Op.FORITER,VM2Op.WFORITER),
    "RAISE":         (VM1Op.RAISE,  VM2Op.WRAISE),
    "IMPORT":        (VM1Op.IMPORT, VM2Op.WIMPORT),
    "IMPORT_FROM":   (VM1Op.IMPORTFROM, VM2Op.WIMPORTFROM),
    "DELETE":        (VM1Op.DELETE, VM2Op.WDELETE),
    "NOP":           (VM1Op.NOP,    VM2Op.NOP),
    "TRY_ENTER":     (VM1Op.TRY_ENTER, VM2Op.WTRY_ENTER),
    "TRY_EXIT":      (VM1Op.TRY_EXIT,  VM2Op.WTRY_EXIT),
    "GLOBAL_DECL":   (VM1Op.GLOBAL,    VM2Op.WGLOBAL),
}
