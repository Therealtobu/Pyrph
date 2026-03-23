"""
Interleaver – converts an IRModule into a VM3 bytecode stream.

Steps
─────
1. For each IRInstruction, look up IR_TO_VM_SPLIT to get (VM1Op, VM2Op).
2. Use Scheduler.schedule_sequence() to assign each instruction a vm_slot
   (0 = VM1 part, 1 = VM2 part).
3. For split-able binary instructions (ADD, SUB, MUL, BAND, BXOR, BOR):
   - VM1 part: compute_part_A (left operand prep + partial op)
   - VM2 part: compute_part_B (right operand prep + final combination)
   This means ADD is NOT simply "VM1 does ADD, VM2 does MUL" – instead the
   computation of a single ADD is physically split between both VMs.
4. Assign cross-key dependencies:
   vm1.key = hash(vm2.state)  after every VM2 instruction
   vm2.key = hash(vm1.last_output)  after every VM1 instruction
5. Build VM3Bytecode: a flat list of VM3Instruction objects that the VM3
   executor will dispatch to vm1_part / vm2_part handlers.

Output: VM3Bytecode (passed to VMCodeGen)
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Any

from ..ir.nodes import IRModule, IRFunction, IRInstruction, IROp
from .opcodes  import IR_TO_VM_SPLIT, VM1Op, VM2Op
from .resolver import OpcodeResolver, make_session_key
from .scheduler import Scheduler

_MASK32 = 0xFFFF_FFFF

# ── VM3 instruction (merged opcode space) ────────────────────────────────────
@dataclass
class VM3Instr:
    enc_op:    int                   # encrypted merged opcode
    vm_slot:   int                   # 0=VM1 part, 1=VM2 part
    operands:  list[Any]             = field(default_factory=list)
    label:     str | None            = None
    is_split_a: bool                 = False   # first half of split instruction
    is_split_b: bool                 = False   # second half of split instruction
    split_tmp:  str | None           = None    # temp register bridging A→B
    raw_op:    int                   = 0       # for codegen reference
    block_key: int                   = 0       # per-block encrypt key
    meta:      dict                  = field(default_factory=dict)


@dataclass
class VM3Bytecode:
    instructions:  list[VM3Instr]
    const_table:   dict              # id → value
    string_table:  dict              # str → id
    seed_key1:     int               # initial key for VM1 resolver
    seed_key2:     int               # initial key for VM2 resolver
    sched_seed:    int               # scheduler PRNG seed
    sched_period:  int               # scheduler AC-wave period
    label_map:     dict[str, int]    # label → instruction index


# ── Split helpers ─────────────────────────────────────────────────────────────
# Binary ops that can be meaningfully split between two VMs:
#   Part A (VM1): load src[0] into a bridge temp, apply left-side partial op
#   Part B (VM2): load src[1], combine with bridge temp to produce dst
_SPLIT_OPS = {
    IROp.ADD, IROp.SUB, IROp.MUL,
    IROp.BAND, IROp.BOR, IROp.BXOR,
    IROp.AND, IROp.OR,
    IROp.CMP_EQ, IROp.CMP_NE, IROp.CMP_LT, IROp.CMP_LE,
    IROp.CMP_GT, IROp.CMP_GE,
}

_tmp_ctr = 0
def _new_split_tmp() -> str:
    global _tmp_ctr
    _tmp_ctr += 1
    return f"__split_{_tmp_ctr}"


class Interleaver:

    def __init__(self, period: int = 32):
        self._period = period

    def interleave(self, module: IRModule) -> VM3Bytecode:
        # Generate session keys
        key1       = make_session_key()
        key2       = make_session_key() ^ 0xCAFE_BABE
        sched_seed = make_session_key()

        res1 = OpcodeResolver(key=key1)
        res2 = OpcodeResolver(key=key2)
        sched = Scheduler(period=self._period, seed=sched_seed)

        all_vm3: list[VM3Instr] = []
        label_map: dict[str, int] = {}

        for fn in module.functions:
            for block in fn.blocks:
                if block.encrypt_key is None:
                    block.encrypt_key = random.randint(1, _MASK32)

                if block.label:
                    label_map[block.label] = len(all_vm3)

                for ir_instr in block.instructions:
                    # Record label

                    vm3_instrs = self._convert_instr(
                        ir_instr, block.encrypt_key, res1, res2, sched
                    )
                    all_vm3.extend(vm3_instrs)
                    # cross_update is called inside _convert_instr / _split_binary
                    # after EACH encode, to match runtime behavior exactly.

        # Merge string_table (str→id) reversed into const_table so str_ref operands work
        merged_consts = dict(module.const_table)
        for s, sid in module.string_table.items():
            if sid not in merged_consts:
                merged_consts[sid] = s

        return VM3Bytecode(
            instructions  = all_vm3,
            const_table   = merged_consts,
            string_table  = dict(module.string_table),
            seed_key1     = key1,
            seed_key2     = key2,
            sched_seed    = sched_seed,
            sched_period  = self._period,
            label_map     = label_map,
        )


    def interleave_function(self, fn, shared_const_table: dict,
                            shared_string_table: dict) -> 'VM3Bytecode':
        """Compile a single IRFunction into its own VM3Bytecode with fresh keys."""
        key1       = make_session_key()
        key2       = make_session_key() ^ 0xCAFE_BABE
        sched_seed = make_session_key()

        res1  = OpcodeResolver(key=key1)
        res2  = OpcodeResolver(key=key2)
        sched = Scheduler(period=self._period, seed=sched_seed)

        all_vm3:   list = []
        label_map: dict = {}

        for block in fn.blocks:
            if block.encrypt_key is None:
                block.encrypt_key = random.randint(1, _MASK32)
            if block.label:
                label_map[block.label] = len(all_vm3)

            for ir_instr in block.instructions:
                vm3_instrs = self._convert_instr(
                    ir_instr, block.encrypt_key, res1, res2, sched)
                all_vm3.extend(vm3_instrs)

        # Merge string values into const_table
        _merged = dict(shared_const_table)
        for _s, _sid in shared_string_table.items():
            if _sid not in _merged:
                _merged[_sid] = _s

        return VM3Bytecode(
            instructions  = all_vm3,
            const_table   = _merged,
            string_table  = shared_string_table,
            seed_key1     = key1,
            seed_key2     = key2,
            sched_seed    = sched_seed,
            sched_period  = self._period,
            label_map     = label_map,
        )

    # ─────────────────────────────────────────────────────────────────────────
    def _convert_instr(self, ir: IRInstruction, block_key: int,
                       res1: OpcodeResolver, res2: OpcodeResolver,
                       sched: Scheduler) -> list[VM3Instr]:
        op_name = ir.op.name
        vm1op, vm2op = IR_TO_VM_SPLIT.get(op_name, (VM1Op.NOP, VM2Op.NOP))

        # Choose vm_slot for this instruction
        last_data = res1.last_output ^ res2.last_output
        vm_slot   = sched.pick_vm(res1, res2, last_data=last_data)

        # Encode opcode with active resolver
        if ir.op in _SPLIT_OPS and len(ir.src) >= 2:
            return self._split_binary(ir, block_key, vm1op, vm2op, res1, res2)
        else:
            raw_op    = vm1op if vm_slot == 0 else vm2op
            resolver  = res1  if vm_slot == 0 else res2
            enc_op    = resolver.encode(int(raw_op))
            # cross_update immediately after encode → matches runtime
            Scheduler.cross_update(res1, res2)
            operands  = self._operands(ir)
            instr = VM3Instr(
                enc_op   = enc_op,
                vm_slot  = vm_slot,
                operands = operands,
                label    = ir.label,
                raw_op   = int(raw_op),
                block_key= block_key,
            )
            if ir.label:
                instr.label = ir.label
            return [instr]

    def _split_binary(self, ir: IRInstruction, block_key: int,
                      vm1op, vm2op,
                      res1: OpcodeResolver, res2: OpcodeResolver
                      ) -> list[VM3Instr]:
        """
        Split a binary instruction into Part A (VM1) and Part B (VM2).

        Part A: RLOAD src[0] into split_tmp   (VM1 slot)
        Part B: apply vm2op(split_tmp, src[1]) → dst  (VM2 slot)
        """
        tmp = _new_split_tmp()
        ops_a = self._operands_partial(ir, side="A", tmp=tmp)
        ops_b = self._operands_partial(ir, side="B", tmp=tmp)

        enc_a = res1.encode(int(VM1Op.RLOAD_VAR))
        # cross_update after part_a encode → matches runtime cross_update after part_a decode
        Scheduler.cross_update(res1, res2)
        enc_b = res2.encode(int(vm2op))
        # cross_update after part_b encode → matches runtime cross_update after part_b decode
        Scheduler.cross_update(res1, res2)

        part_a = VM3Instr(
            enc_op     = enc_a,
            vm_slot    = 0,
            operands   = ops_a,
            is_split_a = True,
            split_tmp  = tmp,
            raw_op     = int(VM1Op.RLOAD_VAR),
            block_key  = block_key,
        )
        part_b = VM3Instr(
            enc_op     = enc_b,
            vm_slot    = 1,
            operands   = ops_b,
            is_split_b = True,
            split_tmp  = tmp,
            raw_op     = int(vm2op),
            block_key  = block_key,
            label      = ir.label,
        )
        return [part_a, part_b]

    # ── Operand conversion ────────────────────────────────────────────────────
    @staticmethod
    def _operands(ir: IRInstruction) -> list:
        ops = []
        if ir.dst:
            ops.append(("dst", ir.dst.kind, ir.dst.value))
        for s in ir.src:
            ops.append(("src", s.kind, s.value))
        if ir.label:
            ops.append(("lbl", "label", ir.label))
        return ops

    @staticmethod
    def _operands_partial(ir: IRInstruction, side: str, tmp: str) -> list:
        if side == "A":
            # Load src[0] into tmp
            src = ir.src[0]
            return [("dst","var", tmp), ("src", src.kind, src.value)]
        else:
            # Apply op: (tmp, src[1]) → dst
            src1 = ir.src[1] if len(ir.src) > 1 else ir.src[0]
            dst  = ir.dst
            ops  = []
            if dst:
                ops.append(("dst", dst.kind, dst.value))
            ops.append(("src", "var", tmp))
            ops.append(("src", src1.kind, src1.value))
            return ops
