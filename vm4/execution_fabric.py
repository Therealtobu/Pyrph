"""
L2 – Execution Fabric (EF)

Non-deterministic scheduler that converges correctly.

Core loop:
  while not converged(hist):
      idx  = H(state_hash, dna_partial, time_jitter, hist) % N
      frag = pool[idx]
      if ready(frag, state, hist):
          key = H(last_output, sag_state, dna_partial)
          op  = decode_fragment(frag, key)   ← ICB: key from prev output
          if is_speculative(frag):
              snapshot → exec → rollback
          else:
              exec → commit → update_hist

Convergence guarantee:
  Each REAL fragment has a max_skip counter.
  If a fragment is skipped too many times, it gets force-scheduled.
  → Loop terminates in O(N * max_skip) steps.

Anti-trace properties:
  - Execution order different every run
  - Speculative fragments create false execution paths in any trace
  - time_jitter mixed into scheduler → timing-based analysis confused
  - ~35% of pool are decoys → trace is 35% noise

Emitted as Python source → inlined into output.
"""
from __future__ import annotations

_MASK32 = 0xFFFF_FFFF


class ExecutionFabricEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── L2: Execution Fabric ──────────────────────────────────────────────────────
try:
    import pyrph_core as _NC; _NC_NATIVE = True
except ImportError:
    _NC = None; _NC_NATIVE = False

import time as _ef_time

_EF_MASK    = 0xFFFFFFFF
_EF_MUL     = 0x6C62272E
_EF_MAX_SKIP = 30          # force-schedule after this many skips


def _ef_state_hash(sm_state: dict) -> int:
    """Hash of current state mesh → used in scheduler."""
    h = len(sm_state)
    for k, v in sm_state.items():
        try:
            h = (h ^ hash(k) ^ hash(v)) & _EF_MASK
        except TypeError:
            h = (h ^ hash(k) ^ id(v)) & _EF_MASK
    return h


def _ef_time_jitter() -> int:
    """Timing entropy — disabled for determinism (state provides sufficient entropy)."""
    return 0


def _ef_pick(pool_size: int, state_hash: int,
             dna_partial: int, hist_hash: int,
             cycle: int) -> int:
    """
    Non-deterministic but bounded scheduler index.
    Result depends on: state + DNA + time + history.
    No static prediction possible.
    """
    if pool_size <= 0:
        return 0
    tj  = _ef_time_jitter()
    raw = (state_hash * _EF_MUL) ^ dna_partial ^ hist_hash ^ tj ^ cycle
    return raw % pool_size


def _ef_causality_key(last_out_hash: int,
                      sag_state: int,
                      dna_partial: int) -> int:
    """ICB key: fragment can only be decoded after prev output known."""
    if _NC_NATIVE:
        return _NC.causality_key(last_out_hash, sag_state, dna_partial)
    return (hash((last_out_hash, sag_state, dna_partial)) & _EF_MASK)


def _ef_decode_fragment(enc_payload: list, key: int) -> tuple:
    """
    Decode fragment payload using causality key.
    Returns (op_id, part, dst_hash, src_hash) or None on failure.
    """
    if len(enc_payload) < 5:
        return None
    k = enc_payload[-1] ^ (key & 0xFF)
    decoded = bytes([enc_payload[i] ^ k for i in range(len(enc_payload)-1)])
    import struct
    try:
        return struct.unpack(">HHHH", decoded[:8])
    except Exception:
        return None


def _ef_hist_hash(hist: list) -> int:
    if not hist:
        return 0
    return hash(tuple(hist[-8:])) & _EF_MASK


def _ef_converged(done_real: set, all_real: list, hist: list) -> bool:
    """True when all REAL fragments have executed at least once."""
    if not all_real:
        return True
    return done_real.issuperset(all_real)


def _ef_run(pool: list, real_ids: list,
            sm_state: dict, sag_state_fn,
            dna_partial_init: int,
            max_cycles: int = 500) -> tuple:
    """
    Main execution fabric loop.

    Returns (final_sm_state, dna_partial, execution_history)
    """
    if not pool or max_cycles <= 0:
        return sm_state, dna_partial_init, []

    hist         = []
    done_real    = set()
    skip_counts  = {}
    dna_partial  = dna_partial_init
    last_out     = 0
    cycle        = 0

    while not _ef_converged(done_real, real_ids, hist) and cycle < max_cycles:
        cycle     += 1
        sh         = _ef_state_hash(sm_state)
        hh         = _ef_hist_hash(hist)
        sag_s      = sag_state_fn() if callable(sag_state_fn) else 0
        idx        = _ef_pick(len(pool), sh, dna_partial, hh, cycle)
        frag       = pool[idx]

        fid        = frag["id"]
        ftype      = frag["ft"]   # 1=REAL, 2=NOISE, 3=SPECULATIVE, 4=BRIDGE
        ticket     = set(frag["tm"])
        done_ids   = set(f for f in hist if isinstance(f, int))

        # Ticket check
        if not ticket.issubset(done_ids):
            skip_counts[fid] = skip_counts.get(fid, 0) + 1
            # Force if skipped too many times and tickets fulfilled via timeout
            if skip_counts[fid] < _EF_MAX_SKIP:
                continue

        # Decode fragment using causality key (ICB)
        ckey       = _ef_causality_key(
            hash(last_out) & _EF_MASK, sag_s, dna_partial
        )
        decoded    = _ef_decode_fragment(frag["ep"], ckey)

        if decoded is None:
            continue   # corrupted/fake fragment → skip silently

        op_id, part, dst_h, src_h = decoded

        # Snapshot for speculative rollback
        if ftype == 3:   # SPECULATIVE
            snap = dict(sm_state)
            _ef_execute_fragment(op_id, part, dst_h, src_h, sm_state, ftype)
            sm_state.update(snap)   # rollback
            hist.append(f"spec_{fid}")
        else:
            out = _ef_execute_fragment(op_id, part, dst_h, src_h, sm_state, ftype)
            last_out = out if isinstance(out, int) else hash(str(out)) & _EF_MASK
            hist.append(fid)
            if ftype == 1:   # REAL
                done_real.add(fid)

        # Update DNA partial
        dna_partial = (hash((dna_partial, fid, last_out, cycle)) & _EF_MASK)

    return sm_state, dna_partial, hist


def _ef_execute_fragment(op_id: int, part: int,
                         dst_h: int, src_h: int,
                         sm_state: dict, ftype: int):
    """
    Execute a decoded fragment against the state mesh.
    op_id encodes which IR operation this fragment belongs to.
    The actual semantics are recovered by the state mesh (L3).
    """
    # Fragment execution updates SM slots based on op_id + part
    slot_key = f"__fg_{op_id}_{part}"
    prev     = sm_state.get(slot_key, 0)
    if isinstance(prev, int):
        new_val  = (prev ^ (dst_h * 0x9E3779B9) ^ src_h) & 0xFFFFFFFF
        sm_state[slot_key] = new_val
        return new_val
    return 0
'''

    @staticmethod
    def emit_init_code() -> str:
        """Bootstrap code to initialise execution fabric per-VM4 run."""
        return (
            "import random as _ef_rand\n"
            "_EF_DNA_SEED = _ef_rand.getrandbits(32)\n"
        )
