# pyrph_core – Rust Native Layer

## What this is

A PyO3 Rust extension that implements all hot-path VM computations natively.

Once compiled, `pyrph_core.so` is a static Linux binary (~2MB).
- No Rust runtime needed on the server
- Works on Railway, Render, Fly.io, Heroku (any Linux x86_64)
- `sys.settrace()` / `frame.f_locals` / `inspect` cannot see Rust frames
- Attacker must use GDB/LLDB or Frida to debug — huge barrier increase

## Functions exposed to Python

| Function | Description |
|----------|-------------|
| `resolve_op(enc,key,state,prev_op,data_flow)` | ResolverV2 opcode decode |
| `ss_write(value,k1,k2)` | Split-state encode → (shard_a, shard_b) |
| `ss_read(shard_a,shard_b,k2)` | Split-state decode → signed int |
| `ss_tick(sa,sb,k1,k2,pc,last_op)` | Re-key SS registers → (sa,sb,k1,k2) |
| `sched_pick(pool_size,state_hash,dna,hist,cycle)` | EF scheduler index |
| `causality_key(last_out,sag_state,dna)` | ICB causality key |
| `dna_step(dna,frag_id,last_out,cycle)` | DNA accumulation step |
| `dna_finalize(dna,order,visits,state,tj)` | DNA lock finalization |
| `sm_derive_keys(var_hash,dna,sag,mcp,base)` | State Mesh key derivation |
| `sm_enc_shard(v,k,noise,idx)` | Encode one SM shard |
| `sm_dec_shard(s,k,noise,idx)` | Decode one SM shard |
| `peil_checkpoint(vm_state,sag,depth,count,hist)` | PEIL integrity hash |
| `peil_corrupt(result,diff)` | Silent corruption formula |
| `ef_state_hash(keys,values)` | EF state hash from KV lists |
| `version()` | Version string |

## Build

```bash
cd native_core/
./build.sh          # outputs ../pyrph_core.so
```

Requires Rust toolchain: https://rustup.rs

For cross-compilation to Linux from macOS:
```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

## Deploy

Upload `pyrph_core.so` next to `bot.py`.
Python will automatically find it via `import pyrph_core`.
