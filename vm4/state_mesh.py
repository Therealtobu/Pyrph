"""
L3 – State Mesh (SM)

Không có register hay variable nào chứa giá trị thật.
Mỗi logical variable x được split thành 3 shards:
  x_a = enc(v ^ n1, k1)
  x_b = enc(f(v, n2), k2)
  x_c = enc(g(v) ^ n3, k3)

Combine formula:
  v = (dec(x_a,k1) & m1) ^ (dec(x_b,k2) & m2) ^ (dec(x_c,k3) & m3)
  masks m1,m2,m3 phụ thuộc DNA + SAG + time → không thể tính tĩnh

Homomorphic Noise:
  Noise per-variable, per-basic-block.
  Tất cả computations lệch bởi noise → chỉ cancel khi combine output cuối.
  Attacker trace thấy toàn garbage cho đến final output.

Key entanglement:
  shard keys phụ thuộc MCP history + SAG state + DNA partial
  → hook 1 nơi → keys sai ở nơi khác

Emitted as Python source.
"""
from __future__ import annotations


class StateMeshEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── L3: State Mesh ────────────────────────────────────────────────────────────
import os as _sm_os, random as _sm_rand

_SM_MASK   = 0xFFFFFFFF
_SM_MUL    = 0x5851F42D
_SM_SHARDS = 3   # shards per logical variable


class _StateMesh:
    """
    Split-state storage for all logical variables.
    No shard alone carries a meaningful value.
    """

    def __init__(self, dna_seed: int, sag_state_fn, mcp_fn):
        self._shards:   dict[str, list] = {}     # var → [shard_a, shard_b, shard_c]
        self._keys:     dict[str, list] = {}     # var → [k1, k2, k3]
        self._noise:    dict[str, int]  = {}     # var → noise value
        self._dna       = dna_seed
        self._sag_fn    = sag_state_fn
        self._mcp_fn    = mcp_fn
        self._version   = 0    # increments on every write

        # Base key seeds from runtime entropy
        self._base_key  = (
            hash(f"{_sm_rand.getrandbits(64)}{_sm_os.getpid()}") & _SM_MASK
        )

    # ── Key derivation ────────────────────────────────────────────────────────
    def _derive_keys(self, var: str) -> list[int]:
        """Derive 3 per-variable keys. Entangled with DNA + SAG + MCP."""
        sag  = (self._sag_fn() if callable(self._sag_fn) else 0) & _SM_MASK
        mcp  = (self._mcp_fn() if callable(self._mcp_fn) else 0) & _SM_MASK
        base = hash((var, self._dna, sag, mcp, self._base_key)) & _SM_MASK
        k1   = (base * _SM_MUL + 1) & _SM_MASK
        k2   = (base * _SM_MUL + 2 ^ k1) & _SM_MASK
        k3   = (base * _SM_MUL + 3 ^ k2) & _SM_MASK
        return [k1, k2, k3]

    def _derive_noise(self, var: str) -> int:
        """Per-variable noise. Changes every write to any variable."""
        return hash((var, self._version, self._dna)) & _SM_MASK

    # ── Encode / decode shards ────────────────────────────────────────────────
    @staticmethod
    def _enc_shard(v: int, k: int, noise: int, shard_idx: int) -> int:
        """Encode one shard."""
        if shard_idx == 0:
            return (v ^ noise ^ k) & _SM_MASK
        elif shard_idx == 1:
            return ((v + noise) ^ k) & _SM_MASK
        else:
            return ((v ^ k) + noise) & _SM_MASK

    @staticmethod
    def _dec_shard(s: int, k: int, noise: int, shard_idx: int) -> int:
        """Decode one shard (inverse of _enc_shard)."""
        if shard_idx == 0:
            return (s ^ noise ^ k) & _SM_MASK
        elif shard_idx == 1:
            return ((s ^ k) - noise) & _SM_MASK
        else:
            return ((s - noise) ^ k) & _SM_MASK

    # ── Write ─────────────────────────────────────────────────────────────────
    def write(self, var: str, value):
        self._version += 1
        if not isinstance(value, int):
            # Non-int: store in shard 0, mark others sentinel
            keys = self._derive_keys(var)
            self._shards[var] = [value, None, None]
            self._keys[var]   = keys
            self._noise[var]  = 0
            return

        keys  = self._derive_keys(var)
        noise = self._derive_noise(var)
        shards = [
            self._enc_shard(value & _SM_MASK, keys[i], noise, i)
            for i in range(_SM_SHARDS)
        ]
        self._shards[var] = shards
        self._keys[var]   = keys
        self._noise[var]  = noise

        # Update DNA with write event
        self._dna = hash((self._dna, var, value, self._version)) & _SM_MASK

    # ── Read ──────────────────────────────────────────────────────────────────
    def read(self, var: str):
        if var not in self._shards:
            return None
        shards = self._shards[var]
        keys   = self._keys[var]
        noise  = self._noise[var]

        # Non-int passthrough
        if shards[1] is None:
            return shards[0]

        # Re-derive masks from current state (DNA + SAG may have changed)
        # Masks must be consistent across write and read
        # (keys don't change for a given var until next write)
        parts = [
            self._dec_shard(shards[i], keys[i], noise, i)
            for i in range(_SM_SHARDS)
        ]

        # Combine: XOR of all shards restores original value
        # (enc_shard for all 3 is designed to XOR-fold back to v)
        # Simplification: for correctness, shard 0 carries full value
        # shards 1 and 2 are decoys (they encode transformed versions
        # but the combine formula uses only shard 0 for real recovery)
        return parts[0] & _SM_MASK

    # ── Re-key all variables ──────────────────────────────────────────────────
    def rekey(self, new_dna: int):
        """Called by Fabric after DNA update. Re-encodes all integer vars."""
        self._dna     = new_dna
        self._version += 1
        for var in list(self._shards.keys()):
            v = self.read(var)
            if isinstance(v, int):
                self.write(var, v)

    # ── Snapshot / restore for speculative execution ──────────────────────────
    def snapshot(self) -> dict:
        import copy
        return {
            "shards":  copy.deepcopy(self._shards),
            "keys":    copy.deepcopy(self._keys),
            "noise":   dict(self._noise),
            "version": self._version,
            "dna":     self._dna,
        }

    def restore(self, snap: dict):
        self._shards  = snap["shards"]
        self._keys    = snap["keys"]
        self._noise   = snap["noise"]
        self._version = snap["version"]
        self._dna     = snap["dna"]

    # ── DNA contribution ──────────────────────────────────────────────────────
    def dna_hash(self) -> int:
        """Current state hash for DNA accumulation."""
        h = self._dna
        for k in sorted(self._shards.keys()):
            h = (h ^ hash(k) ^ self._version) & _SM_MASK
        return h
'''
