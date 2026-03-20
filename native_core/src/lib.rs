//! pyrph_core – Rust/PyO3 native VM core for Pyrph
//! V2: adds parallel engine support + thread-safe shared state

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

const MASK32: u64 = 0xFFFF_FFFF;
const MUL_GLD: u64 = 0x9E37_79B9;
const MUL_ROT: u64 = 0x6C62_272E;
const MUL_SM:  u64 = 0x5851_F42D;

// ── Resolver ─────────────────────────────────────────────────────────────────
#[pyfunction]
fn resolve_op(enc: u64, key: u64, state: u64,
              prev_op: u64, data_flow: u64) -> u64 {
    let base    = ((enc ^ key).wrapping_add(state) ^ (state >> 3)) & MASK32;
    let rotated = (base ^ prev_op.wrapping_mul(MUL_ROT)) & MASK32;
    let fin     = (rotated.wrapping_add(data_flow)
                    ^ ((data_flow << 7) & MASK32)) & MASK32;
    fin
}

// ── Split-State registers ─────────────────────────────────────────────────────
#[pyfunction]
fn ss_write(value: u64, k1: u64, k2: u64) -> (u64, u64) {
    ((value ^ k1) & MASK32, (k1 ^ k2) & MASK32)
}

#[pyfunction]
fn ss_read(shard_a: u64, shard_b: u64, k2: u64) -> i64 {
    let raw = (shard_a ^ shard_b ^ k2) & MASK32;
    if raw >= 0x8000_0000 { (raw as i64) - 0x1_0000_0000i64 } else { raw as i64 }
}

#[pyfunction]
fn ss_tick(sa: u64, sb: u64, k1: u64, k2: u64,
           pc: u64, last_op: u64) -> (u64, u64, u64, u64) {
    let decoded = (sa ^ sb ^ k2) & MASK32;
    let new_k1  = (k1.wrapping_mul(MUL_SM).wrapping_add(pc)) & MASK32;
    let new_k2  = (new_k1 ^ last_op).wrapping_mul(MUL_GLD) & MASK32;
    ((decoded ^ new_k1) & MASK32, (new_k1 ^ new_k2) & MASK32, new_k1, new_k2)
}

// ── Scheduler ────────────────────────────────────────────────────────────────
#[pyfunction]
fn sched_pick(pool_size: u64, state_hash: u64,
              dna: u64, hist_hash: u64, cycle: u64) -> u64 {
    if pool_size == 0 { return 0; }
    let tj  = time_jitter();
    (state_hash.wrapping_mul(MUL_ROT) ^ dna ^ hist_hash ^ tj ^ cycle) % pool_size
}

#[pyfunction]
fn causality_key(last_out: u64, sag_state: u64, dna: u64) -> u64 {
    last_out.wrapping_mul(MUL_GLD)
            .wrapping_add(sag_state)
            .wrapping_mul(MUL_SM)
            .bitxor(dna) & MASK32
}

// ── DNA ───────────────────────────────────────────────────────────────────────
#[pyfunction]
fn dna_step(dna: u64, frag_id: u64, last_out: u64, cycle: u64) -> u64 {
    (dna ^ frag_id.wrapping_mul(MUL_GLD)
        ^ last_out.wrapping_mul(MUL_SM)
        ^ cycle).wrapping_mul(MUL_ROT) & MASK32
}

#[pyfunction]
fn dna_finalize(dna: u64, order_sketch: u64, visit_hash: u64,
                state_hash: u64, time_jitter_val: u64) -> u64 {
    let mut h = dna;
    h = (h ^ order_sketch.wrapping_mul(MUL_GLD)) & MASK32;
    h = (h ^ visit_hash ^ state_hash ^ time_jitter_val) & MASK32;
    h.wrapping_mul(MUL_SM).wrapping_add(1) & MASK32
}

// ── State Mesh ────────────────────────────────────────────────────────────────
#[pyfunction]
fn sm_derive_keys(var_hash: u64, dna: u64, sag: u64,
                  mcp: u64, base_key: u64) -> (u64, u64, u64) {
    let base = (var_hash ^ dna ^ sag ^ mcp ^ base_key).wrapping_mul(MUL_SM) & MASK32;
    let k1 = base.wrapping_mul(MUL_SM).wrapping_add(1) & MASK32;
    let k2 = (base.wrapping_mul(MUL_SM).wrapping_add(2) ^ k1) & MASK32;
    let k3 = (base.wrapping_mul(MUL_SM).wrapping_add(3) ^ k2) & MASK32;
    (k1, k2, k3)
}

#[pyfunction]
fn sm_enc_shard(v: u64, k: u64, noise: u64, idx: u64) -> u64 {
    match idx { 0 => (v ^ noise ^ k) & MASK32, 1 => (v.wrapping_add(noise) ^ k) & MASK32, _ => (v ^ k).wrapping_add(noise) & MASK32 }
}

#[pyfunction]
fn sm_dec_shard(s: u64, k: u64, noise: u64, idx: u64) -> u64 {
    match idx { 0 => (s ^ noise ^ k) & MASK32, 1 => (s ^ k).wrapping_sub(noise) & MASK32, _ => s.wrapping_sub(noise) ^ k & MASK32 }
}

// ── PEIL ──────────────────────────────────────────────────────────────────────
#[pyfunction]
fn peil_checkpoint(vm_state: u64, sag_state: u64,
                   depth: u64, count: u64, hist_hash: u64) -> u64 {
    (vm_state.wrapping_mul(MUL_GLD).wrapping_add(sag_state)
        ^ hist_hash
        ^ depth.wrapping_mul(MUL_SM)
        ^ count.wrapping_mul(MUL_ROT)) & MASK32
}

#[pyfunction]
fn peil_corrupt(result: i64, diff: u64) -> i64 {
    let degree = (diff.count_ones() & 0xF) as u64;
    let noise  = degree.wrapping_mul(MUL_GLD) & MASK32;
    if result > -1000 && result < 1000 { result + (degree as i64 & 3) - 1 }
    else { (result ^ noise as i64) & 0xFFFF_FFFF }
}

// ── EF state hash ─────────────────────────────────────────────────────────────
#[pyfunction]
fn ef_state_hash(keys: Vec<i64>, values: Vec<i64>) -> u64 {
    let mut h: u64 = 0;
    for (k, v) in keys.iter().zip(values.iter()) {
        h = (h ^ (*k as u64).wrapping_mul(MUL_GLD)
               ^ (*v as u64).wrapping_mul(MUL_SM)) & MASK32;
    }
    h
}

// ── Parallel Engine (Mode 1+3): Thread-safe shared state ─────────────────────
#[pyclass]
struct RustSharedState {
    vm3_state:  u64,
    rust_state: u64,
    cross_key:  u64,
    last_vm3:   u64,
    last_rust:  u64,
    turn:       u8,
}

#[pymethods]
impl RustSharedState {
    #[new]
    fn new(vm3_seed: u64, rust_seed: u64) -> Self {
        let ck = Self::compute_ck(vm3_seed, rust_seed);
        RustSharedState {
            vm3_state:  vm3_seed  & MASK32,
            rust_state: rust_seed & MASK32,
            cross_key:  ck,
            last_vm3:   0,
            last_rust:  0,
            turn:       0,
        }
    }

    fn vm3_commit(&mut self, state: u64, out: u64) {
        self.vm3_state = state & MASK32;
        self.last_vm3  = out   & MASK32;
        self.cross_key = Self::compute_ck(self.vm3_state, self.rust_state);
        self.turn = 1;
    }

    fn rust_commit(&mut self, state: u64, out: u64) {
        self.rust_state = state & MASK32;
        self.last_rust  = out   & MASK32;
        self.cross_key  = Self::compute_ck(self.vm3_state, self.rust_state);
        self.turn = 0;
    }

    fn whose_turn(&self) -> u8 { self.turn }
    fn get_cross_key(&self) -> u64 { self.cross_key }
    fn get_vm3_state(&self) -> u64 { self.vm3_state }
    fn get_rust_state(&self) -> u64 { self.rust_state }

    fn combine(&self, vm3_r: i64, rust_r: i64) -> i64 {
        let expected_rust = (vm3_r as u64 ^ self.cross_key) & MASK32;
        let delta = (rust_r as u64 ^ expected_rust) & MASK32;
        if delta == 0 { return vm3_r; }
        let noise = (delta.count_ones() as u64 * MUL_GLD) & 0xFF;
        (vm3_r ^ noise as i64) & 0xFFFF_FFFF
    }

    fn rust_confirmation(&self, vm3_result: i64) -> i64 {
        ((vm3_result as u64 ^ self.cross_key) & MASK32) as i64
    }
}

impl RustSharedState {
    fn compute_ck(vm3: u64, rust: u64) -> u64 {
        (vm3 ^ rust).wrapping_mul(MUL_GLD).wrapping_add(vm3 ^ rust) & MASK32
    }
}

// ── Parallel cross-key update (Mode 3: Interleaved) ──────────────────────────
#[pyfunction]
fn interleave_update(vm3_state: u64, rust_state: u64) -> (u64, u64) {
    // Returns (new_python_key, new_rust_key)
    let ck          = (vm3_state ^ rust_state).wrapping_mul(MUL_GLD) & MASK32;
    let new_py_key  = (ck ^ rust_state.wrapping_mul(MUL_SM)) & MASK32;
    let new_rs_key  = (ck ^ vm3_state.wrapping_mul(MUL_ROT)) & MASK32;
    (new_py_key, new_rs_key)
}

// ── Pe_apply: combine Python+Rust results ────────────────────────────────────
#[pyfunction]
fn pe_combine(vm3_result: i64, vm3_state: u64, rust_state: u64) -> i64 {
    let ck            = (vm3_state ^ rust_state).wrapping_mul(MUL_GLD) & MASK32;
    let rust_expected = (vm3_result as u64 ^ ck) & MASK32;
    // In real execution, Rust confirms via rust_confirmation()
    // Here we simulate: no tampering detected → return unchanged
    vm3_result
}

// ── Utilities ────────────────────────────────────────────────────────────────
#[pyfunction]
fn version() -> &'static str {
    "pyrph_core 0.2.0 – Rust/PyO3 + Parallel Engine"
}

fn time_jitter() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 & 0xFFF)
        .unwrap_or(0)
}

trait BitXor { fn bitxor(self, rhs: u64) -> u64; }
impl BitXor for u64 { fn bitxor(self, rhs: u64) -> u64 { self ^ rhs } }

// ── Module ───────────────────────────────────────────────────────────────────
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
    m.add_function(wrap_pyfunction!(interleave_update,m)?)?;
    m.add_function(wrap_pyfunction!(pe_combine,       m)?)?;
    m.add_function(wrap_pyfunction!(version,          m)?)?;
    m.add_class::<RustSharedState>()?;
    Ok(())
}
