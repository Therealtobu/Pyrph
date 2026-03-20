"""
vm/encryptor.py
===============
Encrypts Pyrph VM bytecode before it gets embedded in the output.

Encryption stack (innermost → outermost):
    raw bytecode
        ↓ byte-permutation (random shuffle)
        ↓ rolling-XOR with multi-byte key (step != 1 for non-linearity)
        ↓ AES-128-CTR  (key lives only in the C runtime .so)

The three layers are independent:
- Permutation defeats frequency analysis on bytecode values.
- XOR adds a per-build key that reconstructed by C from N split fragments.
- AES adds a cryptographically strong layer whose key never appears in Python.

NightGuard decrypts entirely inside the C runtime, in this order:
    AES-CTR → undo-XOR → undo-permutation → run VM
"""
from __future__ import annotations
import random
import struct
from dataclasses import dataclass
from typing import List


# ── Pure-Python AES-128-CTR (used only at build time to encrypt) ──────────
# Matches the C implementation in native/runtime.c exactly.

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


def _xtime(x: int) -> int:
    return ((x << 1) ^ (0x1b if x >> 7 else 0)) & 0xFF


def _aes_key_expand(key: bytes) -> list:
    RCON = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
            0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000]
    def sw(w): return (_SBOX[(w>>24)&0xff]<<24)|(_SBOX[(w>>16)&0xff]<<16)|(_SBOX[(w>>8)&0xff]<<8)|_SBOX[w&0xff]
    def rw(w): return ((w<<8)|(w>>24))&0xFFFFFFFF
    rk = [int.from_bytes(key[4*i:4*i+4],'big') for i in range(4)]
    for i in range(4,44):
        t = rk[i-1]
        if i%4==0: t = sw(rw(t))^RCON[i//4-1]
        rk.append((rk[i-4]^t)&0xFFFFFFFF)
    return rk


def _aes_enc_block(block: bytes, rk: list) -> bytes:
    s = list(block)
    for i in range(4):
        s[4*i]^=(rk[i]>>24)&0xff; s[4*i+1]^=(rk[i]>>16)&0xff
        s[4*i+2]^=(rk[i]>>8)&0xff; s[4*i+3]^=rk[i]&0xff
    for r in range(1,11):
        s = [_SBOX[b] for b in s]
        s[1],s[5],s[9],s[13] = s[5],s[9],s[13],s[1]
        s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
        s[3],s[7],s[11],s[15] = s[15],s[3],s[7],s[11]
        if r < 10:
            for c in range(4):
                a0,a1,a2,a3 = s[c],s[c+4],s[c+8],s[c+12]
                s[c]  =_xtime(a0)^_xtime(a1)^a1^a2^a3
                s[c+4]=a0^_xtime(a1)^_xtime(a2)^a2^a3
                s[c+8]=a0^a1^_xtime(a2)^_xtime(a3)^a3
                s[c+12]=_xtime(a0)^a0^a1^a2^_xtime(a3)
        b = r*4
        for i in range(4):
            s[4*i]^=(rk[b+i]>>24)&0xff; s[4*i+1]^=(rk[b+i]>>16)&0xff
            s[4*i+2]^=(rk[b+i]>>8)&0xff; s[4*i+3]^=rk[b+i]&0xff
    return bytes(s)


def aes_ctr_encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES-128-CTR encrypt/decrypt (same operation)."""
    rk  = _aes_key_expand(key)
    ctr = bytearray(nonce)
    out = bytearray()
    for i in range(0, len(data), 16):
        ks    = _aes_enc_block(bytes(ctr), rk)
        chunk = data[i:i+16]
        out.extend(a^b for a,b in zip(chunk, ks))
        for j in range(15,11,-1):
            ctr[j] = (ctr[j]+1)&0xFF
            if ctr[j]: break
    return bytes(out)


# ── Permutation ───────────────────────────────────────────────────────────

def _apply_perm(data: bytes, perm: List[int]) -> bytes:
    out = bytearray(len(data))
    for i, p in enumerate(perm):
        out[p] = data[i]
    return bytes(out)


def _invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Rolling XOR ───────────────────────────────────────────────────────────

def _rolling_xor(data: bytes, key: List[int], step: int) -> bytes:
    klen = len(key); ki = 0
    out  = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[ki]
        ki     = (ki + step) % klen
    return bytes(out)


# ── Key splitting ─────────────────────────────────────────────────────────

def split_key(key: List[int], n: int, rng: random.Random) -> List[List[int]]:
    """
    Split key into n fragments where XOR of all fragments = original key.
    The full key never exists as a single Python object at runtime.
    """
    frags = [[rng.randint(0,255) for _ in key] for _ in range(n-1)]
    last  = [key[i] for i in range(len(key))]
    for f in frags:
        for i in range(len(key)):
            last[i] ^= f[i]
    frags.append(last)
    return frags


# ── Encrypted payload ─────────────────────────────────────────────────────

@dataclass
class EncryptedPayload:
    ciphertext:  bytes          # AES-CTR( XOR( perm(plaintext) ) )
    xor_key_frags: list         # N lists that XOR together to form xor_key
    xor_step:    int
    inv_perm:    List[int]      # inverse permutation table
    orig_len:    int            # length of original plaintext
    aes_nonce:   bytes          # 16-byte nonce for AES-CTR
    aes_key:     bytes          # 16-byte AES key (only used internally,
                                # embedded in .so at compile time, never in .py)


def encrypt_bytecode(data: bytes,
                     aes_key: bytes,
                     n_key_frags: int = 3,
                     seed: int = None) -> EncryptedPayload:
    """
    Apply three-layer encryption to raw bytecode.

    Parameters
    ----------
    data         : raw VM bytecode bytes
    aes_key      : 16-byte AES key (will be baked into native .so)
    n_key_frags  : number of XOR key fragments to split into
    seed         : optional RNG seed for reproducibility

    Returns
    -------
    EncryptedPayload — embed everything except aes_key into the launcher .py
    """
    rng = random.Random(seed)

    # Layer 1: random byte permutation
    perm     = list(range(len(data)))
    rng.shuffle(perm)
    d_perm   = _apply_perm(data, perm)

    # Layer 2: rolling XOR with random key
    key_len  = rng.randint(32, 64)
    xor_key  = [rng.randint(1, 254) for _ in range(key_len)]
    xor_step = rng.choice([1, 3, 5, 7, 11, 13])
    d_xor    = _rolling_xor(d_perm, xor_key, xor_step)

    # Layer 3: AES-128-CTR
    nonce    = bytes(rng.randint(0,255) for _ in range(16))
    d_aes    = aes_ctr_encrypt(d_xor, aes_key, nonce)

    # Split XOR key
    frags    = split_key(xor_key, n_key_frags, rng)

    return EncryptedPayload(
        ciphertext    = d_aes,
        xor_key_frags = frags,
        xor_step      = xor_step,
        inv_perm      = _invert_perm(perm),
        orig_len      = len(data),
        aes_nonce     = nonce,
        aes_key       = aes_key,
    )
