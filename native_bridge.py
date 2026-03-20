"""
native_bridge.py – Runtime bridge between Python layers and pyrph_core.so

At startup, tries to import pyrph_core (Rust native extension).
If unavailable (dev mode / no .so), falls back to pure Python implementations.

Usage from other modules:
    from native_bridge import NC

    key = NC.resolve_op(enc, key, state, prev_op, data_flow)
    sa, sb = NC.ss_write(value, k1, k2)
    v      = NC.ss_read(sa, sb, k2)
"""
from __future__ import annotations
import os

_MASK32 = 0xFFFF_FFFF
_GLD    = 0x9E3779B9
_ROT    = 0x6C62272E
_SM     = 0x5851F42D


# ── Try native ────────────────────────────────────────────────────────────────
try:
    import pyrph_core as _nc
    _NATIVE = True
except ImportError:
    _NATIVE = False
    _nc     = None


# ── Pure-Python fallbacks ─────────────────────────────────────────────────────
class _PyFallback:
    """Pure-Python implementations — same formulas as Rust."""

    @staticmethod
    def resolve_op(enc: int, key: int, state: int,
                   prev_op: int, data_flow: int) -> int:
        base    = ((enc ^ key) + state) ^ (state >> 3)
        base   &= _MASK32
        rotated = (base ^ (prev_op * _ROT)) & _MASK32
        fin     = (rotated + data_flow) ^ ((data_flow << 7) & _MASK32)
        return fin & _MASK32

    @staticmethod
    def ss_write(value: int, k1: int, k2: int) -> tuple:
        return ((value ^ k1) & _MASK32, (k1 ^ k2) & _MASK32)

    @staticmethod
    def ss_read(sa: int, sb: int, k2: int) -> int:
        raw = (sa ^ sb ^ k2) & _MASK32
        return raw - 0x100000000 if raw >= 0x80000000 else raw

    @staticmethod
    def ss_tick(sa: int, sb: int, k1: int, k2: int,
                pc: int, last_op: int) -> tuple:
        decoded = (sa ^ sb ^ k2) & _MASK32
        new_k1  = ((k1 * _SM) + pc) & _MASK32
        new_k2  = ((new_k1 ^ last_op) * _GLD) & _MASK32
        new_a   = (decoded ^ new_k1) & _MASK32
        new_b   = (new_k1  ^ new_k2) & _MASK32
        return (new_a, new_b, new_k1, new_k2)

    @staticmethod
    def sched_pick(pool_size: int, state_hash: int,
                   dna: int, hist_hash: int, cycle: int) -> int:
        import time
        tj  = time.perf_counter_ns() & 0xFFF
        raw = ((state_hash * _ROT) ^ dna ^ hist_hash ^ tj ^ cycle)
        return raw % max(pool_size, 1)

    @staticmethod
    def causality_key(last_out: int, sag_state: int, dna: int) -> int:
        h = ((last_out * _GLD) + sag_state) * _SM ^ dna
        return h & _MASK32

    @staticmethod
    def dna_step(dna: int, frag_id: int, last_out: int, cycle: int) -> int:
        h = dna ^ (frag_id * _GLD) ^ (last_out * _SM) ^ cycle
        return (h * _ROT) & _MASK32

    @staticmethod
    def dna_finalize(dna: int, order_sketch: int, visit_hash: int,
                     state_hash: int, tj: int) -> int:
        h = (dna ^ (order_sketch * _GLD)) & _MASK32
        h = (h ^ visit_hash ^ state_hash ^ tj) & _MASK32
        return (h * _SM + 1) & _MASK32

    @staticmethod
    def sm_derive_keys(var_hash: int, dna: int, sag: int,
                       mcp: int, base_key: int) -> tuple:
        base = ((var_hash ^ dna ^ sag ^ mcp ^ base_key) * _SM) & _MASK32
        k1   = (base * _SM + 1) & _MASK32
        k2   = ((base * _SM + 2) ^ k1) & _MASK32
        k3   = ((base * _SM + 3) ^ k2) & _MASK32
        return (k1, k2, k3)

    @staticmethod
    def sm_enc_shard(v: int, k: int, noise: int, idx: int) -> int:
        if idx == 0: return (v ^ noise ^ k) & _MASK32
        if idx == 1: return ((v + noise) ^ k) & _MASK32
        return ((v ^ k) + noise) & _MASK32

    @staticmethod
    def sm_dec_shard(s: int, k: int, noise: int, idx: int) -> int:
        if idx == 0: return (s ^ noise ^ k) & _MASK32
        if idx == 1: return ((s ^ k) - noise) & _MASK32
        return ((s - noise) ^ k) & _MASK32

    @staticmethod
    def peil_checkpoint(vm_state: int, sag_state: int,
                        depth: int, count: int, hist_hash: int) -> int:
        mixed = (vm_state * _GLD + sag_state) & _MASK32
        return (mixed ^ hist_hash
                ^ (depth  * _SM)
                ^ (count  * _ROT)) & _MASK32

    @staticmethod
    def peil_corrupt(result: int, diff: int) -> int:
        degree = bin(diff).count('1') & 0xF
        noise  = (degree * _GLD) & _MASK32
        if -1000 < result < 1000:
            return result + (degree & 3) - 1
        return (result ^ noise) & _MASK32

    @staticmethod
    def ef_state_hash(keys: list, values: list) -> int:
        h = 0
        for k, v in zip(keys, values):
            h = (h ^ (k * _GLD) ^ (v * _SM)) & _MASK32
        return h

    @staticmethod
    def version() -> str:
        return "pyrph_core (Python fallback – no .so loaded)"


# ── Public interface ──────────────────────────────────────────────────────────
# NC exposes native if .so loaded, otherwise pure-Python fallback.
# All callers use `NC.fn(...)` — transparent.
NC = _nc if _NATIVE else _PyFallback

NATIVE_AVAILABLE = _NATIVE


def status() -> str:
    if _NATIVE:
        return f"pyrph_core: NATIVE ({_nc.version()})"
    return "pyrph_core: Python fallback (install .so for full protection)"
