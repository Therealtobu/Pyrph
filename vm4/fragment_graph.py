"""
L1 – Fragment Graph (FG)

Core concept:
  Mỗi IR operation → 3-6 fragments không có nghĩa độc lập.
  Fragments tạo thành một DAG có cycles và fake edges.
  Fragment i chỉ decode được sau khi fragment i-1 chạy đúng (ICB baked-in).

Fragment types:
  REAL     – thực sự contribute vào computation
  NOISE    – mutate state nhưng cancel ra ở cuối
  SPECULATIVE – chạy rồi rollback (decoy)
  BRIDGE   – kết nối cross-node deps

Causality key formula:
  key_i = H(prev_output, sag_state, dna_partial) & MASK32
  frag_i_decoded = frag_i_enc ^ key_i
  → Fragment không thể decode nếu không có output của fragment trước
  → Static disassembly impossible
  → Dynamic trace buộc phải execute in-order

Ticket system (đảm bảo convergence):
  Mỗi fragment có ticket_mask = set of fragment IDs phải đã chạy trước.
  Scheduler chỉ run fragment khi tất cả tickets đã fulfilled.
  → Loop luôn terminate trong bounded steps.
"""
from __future__ import annotations
import random
import itertools
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional

_MASK32 = 0xFFFF_FFFF
_ctr    = itertools.count(1)

# ── Fragment type ─────────────────────────────────────────────────────────────
class FragType(Enum):
    REAL        = auto()   # contributes to result
    NOISE       = auto()   # cancels out, confuses trace
    SPECULATIVE = auto()   # executes then rolls back
    BRIDGE      = auto()   # cross-node dependency carrier


# ── Fragment node ─────────────────────────────────────────────────────────────
@dataclass
class Fragment:
    id:          int
    ftype:       FragType
    enc_payload: bytes          # encrypted operation bytes
    ticket_mask: set[int]       # fragments that must run first
    noise_id:    int            # which noise group this belongs to
    ir_op_ref:   str            # original IR op name (for DNA)

    # Runtime fields (filled during execution)
    last_output: Any            = None
    run_count:   int            = 0
    is_done:     bool           = False

    def __hash__(self):
        return self.id

    def ticket_satisfied(self, done_ids: set[int]) -> bool:
        return self.ticket_mask.issubset(done_ids)


# ── Fragment Graph ────────────────────────────────────────────────────────────
@dataclass
class FragmentGraph:
    fragments:   list[Fragment]              = field(default_factory=list)
    edges:       dict[int, list[int]]        = field(default_factory=dict)  # id → successors
    back_edges:  dict[int, list[int]]        = field(default_factory=dict)  # fake cycles
    real_ids:    list[int]                   = field(default_factory=list)  # IDs of REAL frags
    noise_groups: dict[int, list[int]]       = field(default_factory=dict)  # noise_id → [frag_ids]

    def add(self, frag: Fragment):
        self.fragments.append(frag)
        self.edges.setdefault(frag.id, [])
        self.back_edges.setdefault(frag.id, [])
        if frag.ftype == FragType.REAL:
            self.real_ids.append(frag.id)
        if frag.ftype == FragType.NOISE:
            self.noise_groups.setdefault(frag.noise_id, []).append(frag.id)

    def link(self, src_id: int, dst_id: int, is_fake: bool = False):
        if is_fake:
            self.back_edges.setdefault(src_id, []).append(dst_id)
        else:
            self.edges.setdefault(src_id, []).append(dst_id)

    def get(self, frag_id: int) -> Optional[Fragment]:
        for f in self.fragments:
            if f.id == frag_id:
                return f
        return None

    def pool(self) -> list[Fragment]:
        return list(self.fragments)


# ── Fragment Graph Builder ────────────────────────────────────────────────────
class FragmentGraphBuilder:
    """
    Converts a list of (ir_op_name, operands) into a FragmentGraph.
    Each IR op becomes 3-6 fragments.
    30-40% of pool are NOISE or SPECULATIVE decoys.
    """

    def __init__(self,
                 frags_per_op:  int   = 4,
                 decoy_ratio:   float = 0.35):
        self.frags_per_op = frags_per_op
        self.decoy_ratio  = decoy_ratio

    def build(self, ir_instructions: list[dict]) -> FragmentGraph:
        """
        ir_instructions: list of {"op": str, "dst": ..., "src": [...]}
        """
        graph = FragmentGraph()
        prev_real_id: Optional[int] = None
        noise_group  = 0

        for ir_instr in ir_instructions:
            op_name  = ir_instr.get("op", "NOP")
            n_frags  = random.randint(3, self.frags_per_op)
            n_decoys = max(1, int(n_frags * self.decoy_ratio))
            n_real   = n_frags - n_decoys

            real_frags  = []
            noise_frags = []

            # Build real fragments for this op
            for i in range(n_real):
                fid     = next(_ctr)
                payload = self._encode_payload(op_name, ir_instr, i, n_real)
                frag    = Fragment(
                    id          = fid,
                    ftype       = FragType.REAL,
                    enc_payload = payload,
                    ticket_mask = {prev_real_id} if prev_real_id else set(),
                    noise_id    = 0,
                    ir_op_ref   = op_name,
                )
                graph.add(frag)
                real_frags.append(fid)
                if prev_real_id is not None:
                    graph.link(prev_real_id, fid)
                prev_real_id = fid

            # Build noise/speculative decoys
            for i in range(n_decoys):
                fid      = next(_ctr)
                is_spec  = random.random() < 0.3
                ftype    = FragType.SPECULATIVE if is_spec else FragType.NOISE
                payload  = self._encode_noise_payload(noise_group, i)
                # Noise ticket: random subset of real frags (creates fake deps)
                ticket = set(random.sample(real_frags,
                                           min(len(real_frags),
                                               random.randint(0, 2))))
                frag = Fragment(
                    id          = fid,
                    ftype       = ftype,
                    enc_payload = payload,
                    ticket_mask = ticket,
                    noise_id    = noise_group,
                    ir_op_ref   = f"__noise_{noise_group}_{i}",
                )
                graph.add(frag)
                noise_frags.append(fid)
                # Fake back-edges from noise to real (creates apparent cycles)
                if real_frags:
                    target = random.choice(real_frags)
                    graph.link(fid, target, is_fake=True)

            noise_group += 1

        # Add some global cross-node fake edges
        all_ids = [f.id for f in graph.fragments]
        n_fake  = len(all_ids) // 4
        for _ in range(n_fake):
            if len(all_ids) >= 2:
                a, b = random.sample(all_ids, 2)
                graph.link(a, b, is_fake=True)

        return graph

    # ── Payload encoding ──────────────────────────────────────────────────────
    @staticmethod
    def _encode_payload(op: str, instr: dict, part: int, total: int) -> bytes:
        """Encode a fragment of an IR operation into bytes."""
        import struct
        op_id   = hash(op) & 0xFFFF
        part_id = (part << 8) | total
        dst_h   = hash(str(instr.get("dst",  ""))) & 0xFFFF
        src_h   = hash(str(instr.get("src",  []))) & 0xFFFF
        raw     = struct.pack(">HHHH", op_id, part_id, dst_h, src_h)
        # XOR-encrypt with random key (will be re-encrypted with causality key at runtime)
        key     = random.randint(0, 255)
        return bytes([b ^ key for b in raw]) + bytes([key])

    @staticmethod
    def _encode_noise_payload(group: int, idx: int) -> bytes:
        import struct
        return struct.pack(">HH", group & 0xFFFF, idx & 0xFFFF) + b"\xFF\xFF"

    # ── Serialise graph for emission ──────────────────────────────────────────
    def serialise(self, graph: FragmentGraph) -> dict:
        """Convert FragmentGraph to JSON-serialisable dict for codegen."""
        frags = []
        for f in graph.fragments:
            frags.append({
                "id":    f.id,
                "ft":    f.ftype.value,
                "ep":    list(f.enc_payload),
                "tm":    list(f.ticket_mask),
                "ni":    f.noise_id,
                "op":    f.ir_op_ref,
            })
        return {
            "frags":  frags,
            "edges":  {str(k): v for k, v in graph.edges.items()},
            "back":   {str(k): v for k, v in graph.back_edges.items()},
            "real":   graph.real_ids,
            "noise":  {str(k): v for k, v in graph.noise_groups.items()},
        }
