"""
L4 – Output Reconstruction + DNA Lock

Core: không có 'result' trung gian đúng.
Chỉ đúng khi reconstruct + DNA match.

Execution DNA accumulation:
  DNA được build liên tục trong quá trình Fabric chạy:
    dna = H(dna, frag_id, last_output, cycle)

  Cuối cùng finalize:
    dna_final = H(dna_partial, order_sketch, visit_counts, delta_hash, time_jitter)

  DNA dùng để:
    1. Mở khóa combine masks
    2. Chọn extraction paths (r1, r2)
    3. Verify integrity

Reconstruction formula:
  r1  = extract_path_A(sm_state, dna_final)
  r2  = extract_path_B(sm_state, dna_final)
  out = mix(r1, r2, noise_global, hist_hash)

BCN (checksum nhúng vào data flow):
  Không có verify() riêng — mảnh checksum trộn vào state mesh.
  Patch 1 fragment → DNA lệch → reconstruction pick sai path → sai output.
  Delay: fail xảy ra ở output cuối, không tại điểm bị patch.

Non-deterministic DNA property:
  time_jitter (12 bits) được mix vào DNA → replay fail sau vài ms.
"""
from __future__ import annotations


class DNALockEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── L4: DNA Lock + Output Reconstruction ─────────────────────────────────────
import time as _dna_time

_DNA_MASK  = 0xFFFFFFFF
_DNA_MUL   = 0x9E3779B9


def _dna_finalize(dna_partial: int, hist: list,
                  sm_state: dict, visit_counts: dict) -> int:
    """
    Finalize execution DNA from partial accumulation + execution metadata.
    Includes time_jitter → replay after >few ms gives different DNA.
    """
    # Order sketch: hash of last 16 fragment IDs visited
    order_sketch = hash(tuple(
        x for x in hist[-16:] if isinstance(x, int)
    )) & _DNA_MASK

    # Visit counts: how many times each real fragment ran
    visit_h = hash(tuple(sorted(visit_counts.items()))) & _DNA_MASK

    # State delta hash
    state_h = hash(tuple(sorted(
        (k, v) for k, v in sm_state.items()
        if isinstance(v, int)
    ))) & _DNA_MASK

    # Time jitter (12 low bits ≈ 4µs window)
    try:
        tj = _dna_time.perf_counter_ns() & 0xFFF
    except Exception:
        tj = 0

    # Combine all sources
    dna = dna_partial
    dna = (dna ^ (order_sketch * _DNA_MUL)) & _DNA_MASK
    dna = (dna ^ visit_h ^ state_h ^ tj)    & _DNA_MASK
    dna = (dna * _DNA_MUL + 1)               & _DNA_MASK
    return dna


def _dna_extract_path_a(sm_state: dict, dna: int) -> int:
    """
    Extract r1 from state mesh using DNA-derived keys.
    Path A: even-indexed slots XOR-folded.
    """
    h = 0
    mask_a = (dna * _DNA_MUL) & 0xFFFF
    for k, v in sm_state.items():
        if isinstance(v, int) and hash(k) % 2 == 0:
            h = (h ^ (v & mask_a)) & _DNA_MASK
    return h


def _dna_extract_path_b(sm_state: dict, dna: int) -> int:
    """
    Extract r2 from state mesh using DNA-derived keys.
    Path B: odd-indexed slots, different mixing.
    """
    h = 0
    mask_b = (dna >> 8) & 0xFFFF
    for k, v in sm_state.items():
        if isinstance(v, int) and hash(k) % 2 == 1:
            h = (h ^ (v | mask_b)) & _DNA_MASK
    return h


def _dna_mix(r1: int, r2: int, hist_hash: int, dna: int) -> int:
    """
    Combine r1 + r2 into final output.
    The mix formula uses DNA → wrong DNA → wrong mix → wrong output.
    """
    noise_g = (dna ^ hist_hash) & 0xFFFF
    # r1 contributes high bits, r2 low bits, combined via DNA-keyed rotation
    rotation = dna % 16
    r1_rot   = ((r1 << rotation) | (r1 >> (32 - rotation))) & _DNA_MASK
    combined = (r1_rot ^ r2 ^ noise_g) & _DNA_MASK
    return combined


def _dna_reconstruct(sm_state: dict, dna_partial: int,
                     hist: list, visit_counts: dict) -> int:
    """
    Full reconstruction pipeline:
    finalize DNA → extract r1/r2 → mix → return.
    """
    dna      = _dna_finalize(dna_partial, hist, sm_state, visit_counts)
    r1       = _dna_extract_path_a(sm_state, dna)
    r2       = _dna_extract_path_b(sm_state, dna)
    hist_h   = hash(tuple(x for x in hist[-8:] if isinstance(x, int))) & _DNA_MASK
    result   = _dna_mix(r1, r2, hist_h, dna)
    return result


def _dna_lock_check(expected_dna_hint: int, actual_dna: int) -> bool:
    """
    Soft lock check — does not raise, just returns bool.
    BCN: if False, mix formula uses corrupted masks.
    """
    # Use only partial comparison to avoid false positives from time_jitter
    return (expected_dna_hint & 0xFFFF) == (actual_dna & 0xFFFF)
'''
