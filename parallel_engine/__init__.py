"""
parallel_engine – Hybrid Parallel Dual-Engine (Stage 9.5)

3 mechanisms combined:

Cách 1 – Thread Parallel:
  Python VM3 và Rust engine chạy trong 2 threads song song.
  Shared state qua thread-safe Arc<Mutex<>> (Rust side) + queue (Python side).

Cách 2 – Process Parallel (IPC):
  Rust spawns subprocess với unix socket / pipe.
  Python và Rust là 2 process độc lập → attacker phải attach cả 2.

Cách 3 – Interleaved Execution:
  Instruction i → Python VM3
  Instruction i+1 → Rust Engine (needs Python state from i)
  Instruction i+2 → Python (needs Rust state from i+1)
  Cross-state dependency: mỗi instruction phụ thuộc instruction trước ở engine khác.

Kết quả cuối:
  final = combine(vm3_result, rust_result, cross_key)
  cross_key = hash(vm3_final_state ^ rust_final_state)
  → Thiếu 1 engine → cross_key sai → combine sai → output sai
"""
