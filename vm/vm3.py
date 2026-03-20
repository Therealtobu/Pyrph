"""
VM3 – Merged opcode executor.

VM3 does NOT unpack/decompress and re-run VM1/VM2 bytecode.
Instead, every VM3 opcode *is* the merged logic of VM1 and VM2:
  - opcode is decrypted with the polymorphic resolver
  - if vm_slot == 0: dispatch to _vm1_part handler
  - if vm_slot == 1: dispatch to _vm2_part handler
  - split instructions (is_split_a / is_split_b) share a cross-VM
    bridge register (__split_N) held in a shared namespace

Cross-key dependency:
  After each VM1 instruction:  vm2_resolver.key = hash(vm1_resolver.last_output)
  After each VM2 instruction:  vm1_resolver.key = hash(vm2_resolver.state)

If an attacker dumps VM1's state mid-run they get wrong vm2 keys → wrong decode.
If they dump VM2 they get wrong vm1 keys → wrong decode.

Polymorphic opcode:
  VM3 has NO static opcode map.  It uses two OpcodeResolver instances
  (one per vm_slot) that carry live state.  The same encoded bytecode
  produces different resolved opcode values on every run because the
  resolvers are seeded from time+pid+random.
"""
from __future__ import annotations
import math
from typing import Any

from .resolver  import OpcodeResolver, make_session_key
from .scheduler import Scheduler
from .opcodes   import VM1Op, VM2Op
from .interleaver import VM3Bytecode, VM3Instr

_MASK32 = 0xFFFF_FFFF


class VM3:
    """
    Executes a VM3Bytecode stream produced by the Interleaver.
    Embeds two full VM frames (VM1-style regs + stack, VM2-style regs + deque)
    inside one unified execution context.
    """

    def __init__(self, bytecode: VM3Bytecode):
        self.bc     = bytecode
        self.res1   = OpcodeResolver(key=bytecode.seed_key1)
        self.res2   = OpcodeResolver(key=bytecode.seed_key2)
        self.sched  = Scheduler(period=bytecode.sched_period,
                                seed=bytecode.sched_seed)
        # Shared namespace for cross-VM bridge registers + variables
        self.env: dict[str, Any] = {}

        # VM1 state (registers r0..r15 + stack)
        self.r1:    list[Any] = [None] * 16
        self.stk1:  list[Any] = []

        # VM2 state (registers w0..w15 + deque) – operand order reversed
        self.r2:    list[Any] = [None] * 16
        self.stk2:  list[Any] = []

        # Label → instruction index
        self.lbl: dict[str, int] = bytecode.label_map
        self.pc:  int            = 0
        self.result: Any         = _STOP

    # ── Public entry ──────────────────────────────────────────────────────────
    def run(self, init_env: dict | None = None) -> Any:
        if init_env:
            self.env.update(init_env)
        instrs = self.bc.instructions

        while self.pc < len(instrs):
            vm3i = instrs[self.pc]
            self.pc += 1

            # Resolve opcode with the correct resolver
            if vm3i.vm_slot == 0:
                real_op = self.res1.resolve(vm3i.enc_op)
                self._exec_vm1(real_op, vm3i)
                # Cross-key: after VM1 → update VM2 key
                self.res2.key = hash(self.res1.last_output) & _MASK32
            else:
                real_op = self.res2.resolve(vm3i.enc_op)
                self._exec_vm2(real_op, vm3i)
                # Cross-key: after VM2 → update VM1 key
                self.res1.key = hash(self.res2.state) & _MASK32

            if self.result is not _STOP:
                return self.result

        return None

    # ── VM1 part dispatcher ───────────────────────────────────────────────────
    def _exec_vm1(self, op: int, i: VM3Instr):
        ops = i.operands
        o   = op & 0xFF    # normalise

        def dst(): return self._op_dst(ops)
        def s(n):  return self._op_src(ops, n)
        def lbl(): return self._op_lbl(ops)

        if o == VM1Op.NOP:    return
        if o == VM1Op.HALT:   self.result = self._rget1(0); return
        if o == VM1Op.RLOAD_CONST:
            self._rset1(dst(), self.bc.const_table.get(s(0))); return
        if o == VM1Op.RLOAD_VAR:
            self._rset1(dst(), self.env.get(str(s(0)))); return
        if o == VM1Op.RSTORE_VAR:
            self.env[str(s(1))] = self._rget1(dst()); return
        if o == VM1Op.RADD:
            self._rset1(dst(), self._rget1(s(0)) + self._rget1(s(1))); return
        if o == VM1Op.RSUB:
            self._rset1(dst(), self._rget1(s(0)) - self._rget1(s(1))); return
        if o == VM1Op.RMUL:
            self._rset1(dst(), self._rget1(s(0)) * self._rget1(s(1))); return
        if o == VM1Op.RDIV:
            self._rset1(dst(), self._rget1(s(0)) / self._rget1(s(1))); return
        if o == VM1Op.RFLOOR:
            self._rset1(dst(), self._rget1(s(0)) // self._rget1(s(1))); return
        if o == VM1Op.RMOD:
            self._rset1(dst(), self._rget1(s(0)) % self._rget1(s(1))); return
        if o == VM1Op.RNEG:
            self._rset1(dst(), -self._rget1(s(0))); return
        if o == VM1Op.RBAND:
            self._rset1(dst(), self._rget1(s(0)) & self._rget1(s(1))); return
        if o == VM1Op.RBOR:
            self._rset1(dst(), self._rget1(s(0)) | self._rget1(s(1))); return
        if o == VM1Op.RBXOR:
            self._rset1(dst(), self._rget1(s(0)) ^ self._rget1(s(1))); return
        if o == VM1Op.RBNOT:
            self._rset1(dst(), ~self._rget1(s(0))); return
        if o == VM1Op.RLSHIFT:
            self._rset1(dst(), self._rget1(s(0)) << self._rget1(s(1))); return
        if o == VM1Op.RRSHIFT:
            self._rset1(dst(), self._rget1(s(0)) >> self._rget1(s(1))); return
        if o == VM1Op.RCEQ:
            self._rset1(dst(), self._rget1(s(0)) == self._rget1(s(1))); return
        if o == VM1Op.RCNE:
            self._rset1(dst(), self._rget1(s(0)) != self._rget1(s(1))); return
        if o == VM1Op.RCLT:
            self._rset1(dst(), self._rget1(s(0)) <  self._rget1(s(1))); return
        if o == VM1Op.RCLE:
            self._rset1(dst(), self._rget1(s(0)) <= self._rget1(s(1))); return
        if o == VM1Op.RCGT:
            self._rset1(dst(), self._rget1(s(0)) >  self._rget1(s(1))); return
        if o == VM1Op.RCGE:
            self._rset1(dst(), self._rget1(s(0)) >= self._rget1(s(1))); return
        if o == VM1Op.RCIS:
            self._rset1(dst(), self._rget1(s(0)) is self._rget1(s(1))); return
        if o == VM1Op.RCIN:
            self._rset1(dst(), self._rget1(s(0)) in self._rget1(s(1))); return
        if o == VM1Op.JMP:    self.pc = self.lbl[lbl()]; return
        if o == VM1Op.JMPT:
            if self._rget1(dst()): self.pc = self.lbl[lbl()]
            return
        if o == VM1Op.JMPF:
            if not self._rget1(dst()): self.pc = self.lbl[lbl()]
            return
        if o == VM1Op.CALL:
            fn   = self._rget1(dst())
            args = [self._rget1(s(n)) for n in range(len(ops)-1)]
            self._rset1(dst(), fn(*args)); return
        if o == VM1Op.RET:
            self.result = self._rget1(dst()) if dst() is not None else None
            return
        if o == VM1Op.SPUSH: self.stk1.append(self._rget1(dst())); return
        if o == VM1Op.SPOP:  self._rset1(dst(), self.stk1.pop()); return
        if o == VM1Op.GETITER:
            self._rset1(dst(), iter(self._rget1(s(0)))); return
        if o == VM1Op.FORITER:
            try:    self._rset1(dst(), next(self._rget1(s(0))))
            except StopIteration: self.pc = self.lbl[lbl()]
            return
        if o == VM1Op.IMPORT:
            self.env[str(dst())] = __import__(str(s(0))); return

    # ── VM2 part dispatcher ───────────────────────────────────────────────────
    def _exec_vm2(self, op: int, i: VM3Instr):
        ops = i.operands
        o   = op & 0xFF

        def dst(): return self._op_dst(ops)
        def s(n):  return self._op_src(ops, n)
        def lbl(): return self._op_lbl(ops)

        if o == VM2Op.NOP:   return
        if o == VM2Op.HALT:  self.result = self._rget2(0); return
        if o == VM2Op.WLOAD_K:
            self._rset2(s(1), self.bc.const_table.get(s(0))); return
        if o == VM2Op.WLOAD_V:
            self._rset2(s(1), self.env.get(str(s(0)))); return
        if o == VM2Op.WSTORE_V:
            self.env[str(s(1))] = self._rget2(s(0)); return
        if o == VM2Op.WADD:
            self._rset2(s(2), self._rget2(s(0)) + self._rget2(s(1))); return
        if o == VM2Op.WSUB:
            self._rset2(s(2), self._rget2(s(0)) - self._rget2(s(1))); return
        if o == VM2Op.WMUL:
            self._rset2(s(2), self._rget2(s(0)) * self._rget2(s(1))); return
        if o == VM2Op.WDIV:
            self._rset2(s(2), self._rget2(s(0)) / self._rget2(s(1))); return
        if o == VM2Op.WFLOOR:
            self._rset2(s(2), self._rget2(s(0)) // self._rget2(s(1))); return
        if o == VM2Op.WMOD:
            self._rset2(s(2), self._rget2(s(0)) % self._rget2(s(1))); return
        if o == VM2Op.WNEG:
            self._rset2(s(1), -self._rget2(s(0))); return
        if o == VM2Op.WBAND:
            self._rset2(s(2), self._rget2(s(0)) & self._rget2(s(1))); return
        if o == VM2Op.WBOR:
            self._rset2(s(2), self._rget2(s(0)) | self._rget2(s(1))); return
        if o == VM2Op.WBXOR:
            self._rset2(s(2), self._rget2(s(0)) ^ self._rget2(s(1))); return
        if o == VM2Op.WBNOT:
            self._rset2(s(1), ~self._rget2(s(0))); return
        if o == VM2Op.WLSH:
            self._rset2(s(2), self._rget2(s(0)) << self._rget2(s(1))); return
        if o == VM2Op.WRSH:
            self._rset2(s(2), self._rget2(s(0)) >> self._rget2(s(1))); return
        if o == VM2Op.WCEQ:
            self._rset2(s(2), self._rget2(s(0)) == self._rget2(s(1))); return
        if o == VM2Op.WCNE:
            self._rset2(s(2), self._rget2(s(0)) != self._rget2(s(1))); return
        if o == VM2Op.WCLT:
            self._rset2(s(2), self._rget2(s(0)) <  self._rget2(s(1))); return
        if o == VM2Op.WCLE:
            self._rset2(s(2), self._rget2(s(0)) <= self._rget2(s(1))); return
        if o == VM2Op.WCGT:
            self._rset2(s(2), self._rget2(s(0)) >  self._rget2(s(1))); return
        if o == VM2Op.WCGE:
            self._rset2(s(2), self._rget2(s(0)) >= self._rget2(s(1))); return
        if o == VM2Op.WJMP:   self.pc = self.lbl[lbl()]; return
        if o == VM2Op.WJMPT:
            if self._rget2(s(0)): self.pc = self.lbl[lbl()]
            return
        if o == VM2Op.WJMPF:
            if not self._rget2(s(0)): self.pc = self.lbl[lbl()]
            return
        if o == VM2Op.WCALL:
            fn   = self._rget2(s(0))
            args = [self._rget2(s(n+1)) for n in range(len(ops)-2)]
            self._rset2(s(0), fn(*args)); return
        if o == VM2Op.WRET:
            self.result = self._rget2(s(0)) if s(0) is not None else None
            return
        if o == VM2Op.WGETITER:
            self._rset2(s(1), iter(self._rget2(s(0)))); return
        if o == VM2Op.WFORITER:
            try:    self._rset2(s(1), next(self._rget2(s(0))))
            except StopIteration: self.pc = self.lbl[lbl()]
            return
        if o == VM2Op.WIMPORT:
            self.env[str(s(1))] = __import__(str(s(0))); return

    # ── Register helpers ──────────────────────────────────────────────────────
    def _rget1(self, key):
        if key is None: return None
        if isinstance(key, int): return self.r1[key & 0xF]
        return self.env.get(str(key))

    def _rset1(self, key, val):
        if key is None: return
        if isinstance(key, int): self.r1[key & 0xF] = val
        else: self.env[str(key)] = val

    def _rget2(self, key):
        if key is None: return None
        if isinstance(key, int): return self.r2[key & 0xF]
        return self.env.get(str(key))

    def _rset2(self, key, val):
        if key is None: return
        if isinstance(key, int): self.r2[key & 0xF] = val
        else: self.env[str(key)] = val

    # ── Operand extractors ────────────────────────────────────────────────────
    @staticmethod
    def _op_dst(ops: list):
        for kind, typ, val in ops:
            if kind == "dst": return val
        return None

    @staticmethod
    def _op_src(ops: list, n: int):
        srcs = [val for kind, typ, val in ops if kind == "src"]
        return srcs[n] if n < len(srcs) else None

    @staticmethod
    def _op_lbl(ops: list):
        for kind, typ, val in ops:
            if kind == "lbl": return val
        return None


_STOP = object()
