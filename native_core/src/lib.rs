//! pyrph_core – Rust/PyO3 native VM core for Pyrph
//!
//! Exposes these Python-callable functions:
//!   pyrph_core.resolve_op(enc, key, state, prev_op, data_flow) -> int
//!   pyrph_core.ss_write(slot, value, k1, k2) -> (int, int)
//!   pyrph_core.ss_read(shard_a, shard_b, k2) -> int
//!   pyrph_core.ss_tick(shard_a, shard_b, k1, k2, pc, last_op) -> (int,int,int,int)
//!   pyrph_core.sched_pick(pool_size, state_hash, dna, hist, cycle) -> int
//!   pyrph_core.causality_key(last_out, sag_state, dna) -> int
//!   pyrph_core.dna_step(dna, frag_id, last_out, cycle) -> int
//!   pyrph_core.dna_finalize(dna, order_sketch, visit_hash, state_hash, tj) -> int
//!   pyrph_core.sm_derive_keys(var_hash, dna, sag, mcp, base_key) -> (int,int,int)
//!   pyrph_core.sm_enc_shard(v, k, noise, idx) -> int
//!   pyrph_core.sm_dec_shard(s, k, noise, idx) -> int
//!   pyrph_core.peil_checkpoint(vm_state, sag_state, depth, count, hist_hash) -> int
//!   pyrph_core.peil_corrupt(result, diff) -> int
//!   pyrph_core.ef_state_hash(keys, values) -> int
//!   pyrph_core.version() -> str

use pyo3::prelude::*;

const MASK32: u64 = 0xFFFF_FFFF;
const MUL_GLD: u64 = 0x9E37_79B9;
const MUL_ROT: u64 = 0x6C62_272E;
const MUL_SM:  u64 = 0x5851_F42D;

// ─────────────────────────────────────────────────────────────────────────────
// Polymorphic opcode resolver (ResolverV2)
// Formula: base = ((enc^key)+state)^(state>>3)
//          rotated = base ^ (prev_op * ROTMUL)
//          final = (rotated + data_flow) ^ (data_flow << 7)
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn resolve_op(enc: u64, key: u64, state: u64,
              prev_op: u64, data_flow: u64) -> u64 {
    let base    = ((enc ^ key).wrapping_add(state) ^ (state >> 3)) & MASK32;
    let rotated = (base ^ prev_op.wrapping_mul(MUL_ROT)) & MASK32;
    let fin     = (rotated.wrapping_add(data_flow)
                    ^ ((data_flow << 7) & MASK32)) & MASK32;
    fin
}

// ─────────────────────────────────────────────────────────────────────────────
// Split-State register (_SS) operations
// Encoding: shard_a = (v ^ k1), shard_b = (k1 ^ k2)
// Decode:   v = shard_a ^ shard_b ^ k2
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn ss_write(value: u64, k1: u64, k2: u64) -> (u64, u64) {
    let shard_a = (value ^ k1) & MASK32;
    let shard_b = (k1    ^ k2) & MASK32;
    (shard_a, shard_b)
}

#[pyfunction]
fn ss_read(shard_a: u64, shard_b: u64, k2: u64) -> i64 {
    let raw = (shard_a ^ shard_b ^ k2) & MASK32;
    // Convert to signed 32-bit
    if raw >= 0x8000_0000 {
        (raw as i64) - 0x1_0000_0000i64
    } else {
        raw as i64
    }
}

/// Re-encode shards with new keys after a tick.
/// Returns (new_shard_a, new_shard_b, new_k1, new_k2)
#[pyfunction]
fn ss_tick(shard_a: u64, shard_b: u64, k1: u64, k2: u64,
           pc: u64, last_op: u64) -> (u64, u64, u64, u64) {
    // Decode with old keys
    let decoded = (shard_a ^ shard_b ^ k2) & MASK32;
    // Advance keys
    let new_k1  = (k1.wrapping_mul(MUL_SM).wrapping_add(pc)) & MASK32;
    let new_k2  = (new_k1 ^ last_op).wrapping_mul(MUL_GLD) & MASK32; // hash-ish
    // Re-encode
    let new_a   = (decoded ^ new_k1) & MASK32;
    let new_b   = (new_k1  ^ new_k2) & MASK32;
    (new_a, new_b, new_k1, new_k2)
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution Fabric scheduler
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn sched_pick(pool_size: u64, state_hash: u64,
              dna: u64, hist_hash: u64, cycle: u64) -> u64 {
    if pool_size == 0 { return 0; }
    let tj  = time_jitter();
    let raw = state_hash.wrapping_mul(MUL_ROT)
              ^ dna
              ^ hist_hash
              ^ tj
              ^ cycle;
    raw % pool_size
}

#[pyfunction]
fn causality_key(last_out: u64, sag_state: u64, dna: u64) -> u64 {
    // Simple multiplicative hash of the three inputs
    let h = last_out
        .wrapping_mul(MUL_GLD)
        .wrapping_add(sag_state)
        .wrapping_mul(MUL_SM)
        ^ dna;
    h & MASK32
}

// ─────────────────────────────────────────────────────────────────────────────
// DNA accumulation / finalization
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn dna_step(dna: u64, frag_id: u64, last_out: u64, cycle: u64) -> u64 {
    // Rolling hash update – one step per fragment execution
    let h = dna
        ^ frag_id.wrapping_mul(MUL_GLD)
        ^ last_out.wrapping_mul(MUL_SM)
        ^ cycle;
    h.wrapping_mul(MUL_ROT) & MASK32
}

#[pyfunction]
fn dna_finalize(dna: u64, order_sketch: u64, visit_hash: u64,
                state_hash: u64, time_jitter_val: u64) -> u64 {
    let mut h = dna;
    h = (h ^ order_sketch.wrapping_mul(MUL_GLD)) & MASK32;
    h = (h ^ visit_hash ^ state_hash ^ time_jitter_val) & MASK32;
    h.wrapping_mul(MUL_SM).wrapping_add(1) & MASK32
}

// ─────────────────────────────────────────────────────────────────────────────
// State Mesh key derivation + shard encoding
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn sm_derive_keys(var_hash: u64, dna: u64, sag: u64,
                  mcp: u64, base_key: u64) -> (u64, u64, u64) {
    let base = (var_hash ^ dna ^ sag ^ mcp ^ base_key)
               .wrapping_mul(MUL_SM) & MASK32;
    let k1 = base.wrapping_mul(MUL_SM).wrapping_add(1) & MASK32;
    let k2 = (base.wrapping_mul(MUL_SM).wrapping_add(2) ^ k1) & MASK32;
    let k3 = (base.wrapping_mul(MUL_SM).wrapping_add(3) ^ k2) & MASK32;
    (k1, k2, k3)
}

#[pyfunction]
fn sm_enc_shard(v: u64, k: u64, noise: u64, idx: u64) -> u64 {
    match idx {
        0 => (v ^ noise ^ k) & MASK32,
        1 => ((v.wrapping_add(noise)) ^ k) & MASK32,
        _ => ((v ^ k).wrapping_add(noise)) & MASK32,
    }
}

#[pyfunction]
fn sm_dec_shard(s: u64, k: u64, noise: u64, idx: u64) -> u64 {
    match idx {
        0 => (s ^ noise ^ k) & MASK32,
        1 => ((s ^ k).wrapping_sub(noise)) & MASK32,
        _ => (s.wrapping_sub(noise) ^ k) & MASK32,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PEIL checkpoint + corruption
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn peil_checkpoint(vm_state: u64, sag_state: u64,
                   depth: u64, count: u64, hist_hash: u64) -> u64 {
    let mixed = vm_state
        .wrapping_mul(MUL_GLD)
        .wrapping_add(sag_state) & MASK32;
    (mixed
        ^ hist_hash
        ^ depth.wrapping_mul(0x5851_F42D)
        ^ count.wrapping_mul(MUL_ROT)) & MASK32
}

#[pyfunction]
fn peil_corrupt(result: i64, diff: u64) -> i64 {
    // degree = popcount(diff) & 0xF
    let degree = (diff.count_ones() & 0xF) as u64;
    let noise  = degree.wrapping_mul(MUL_GLD) & MASK32;
    if result > -1000 && result < 1000 {
        result + (degree as i64 & 3) - 1
    } else {
        (result ^ noise as i64) & 0xFFFF_FFFF
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EF state hash over Python dict-like lists
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn ef_state_hash(keys: Vec<i64>, values: Vec<i64>) -> u64 {
    let mut h: u64 = 0;
    for (k, v) in keys.iter().zip(values.iter()) {
        let kh = (*k as u64).wrapping_mul(MUL_GLD);
        let vh = (*v as u64).wrapping_mul(MUL_SM);
        h = (h ^ kh ^ vh) & MASK32;
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Version
// ─────────────────────────────────────────────────────────────────────────────
#[pyfunction]
fn version() -> &'static str {
    "pyrph_core 0.1.0 – Rust/PyO3 VM native layer"
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────
fn time_jitter() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 & 0xFFF)
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Module registration
// ─────────────────────────────────────────────────────────────────────────────
#[pymodule]
fn pyrph_core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(resolve_op,       m)?)?;
    m.add_function(wrap_pyfunction!(ss_write,         m)?)?;
    m.add_function(wrap_pyfunction!(ss_read,          m)?)?;
    m.add_function(wrap_pyfunction!(ss_tick,          m)?)?;
    m.add_function(wrap_pyfunction!(sched_pick,       m)?)?;
    m.add_function(wrap_pyfunction!(causality_key,    m)?)?;
    m.add_function(wrap_pyfunction!(dna_step,         m)?)?;
    m.add_function(wrap_pyfunction!(dna_finalize,     m)?)?;
    m.add_function(wrap_pyfunction!(sm_derive_keys,   m)?)?;
    m.add_function(wrap_pyfunction!(sm_enc_shard,     m)?)?;
    m.add_function(wrap_pyfunction!(sm_dec_shard,     m)?)?;
    m.add_function(wrap_pyfunction!(peil_checkpoint,  m)?)?;
    m.add_function(wrap_pyfunction!(peil_corrupt,     m)?)?;
    m.add_function(wrap_pyfunction!(ef_state_hash,    m)?)?;
    m.add_function(wrap_pyfunction!(version,          m)?)?;
    Ok(())
}
