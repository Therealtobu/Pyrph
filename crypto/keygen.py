"""
crypto/keygen.py
=================
Dynamic runtime key generation for Pyrph.

Keys are never static constants — they are derived at obfuscation time
from multiple entropy sources, making each build produce a cryptographically
unique key even when run twice on the same machine.

Entropy sources used:
  - os.urandom(32)         — CSPRNG
  - time.time_ns()         — nanosecond timestamp
  - platform fingerprint   — Python version, platform string
  - random seed            — per-build random state
"""
from __future__ import annotations
import hashlib
import os
import platform
import random
import time


def generate_aes_key(seed: int = None) -> bytes:
    """
    Generate a fresh 16-byte AES key from mixed entropy sources.
    Every call produces a different key.
    """
    rng = random.Random(seed)

    entropy = (
        os.urandom(32) +
        time.time_ns().to_bytes(8, "little") +
        platform.python_version().encode() +
        platform.platform().encode() +
        rng.randbytes(32)
    )
    digest = hashlib.sha256(entropy).digest()
    # Take first 16 bytes, ensure no zero bytes (avoid C string termination issues)
    key = bytearray(digest[:16])
    for i in range(16):
        if key[i] == 0:
            key[i] = (digest[i + 16] % 254) + 1
    return bytes(key)


def generate_xor_key(length: int = 32, seed: int = None) -> list:
    """
    Generate a random XOR key of given length.
    All bytes are non-zero (1–254) to avoid zero-byte patterns.
    """
    rng = random.Random(seed)
    return [rng.randint(1, 254) for _ in range(length)]


def derive_key_from_nonce(base_key: bytes, nonce: bytes) -> bytes:
    """
    Derive a session-specific key by mixing base_key with nonce.
    Used for per-invocation key diversity.
    """
    material = base_key + nonce
    return hashlib.sha256(material).digest()[:16]


def split_key(key: list, n: int, seed: int = None) -> list:
    """
    Split key into n fragments such that XOR of all = original key.
    The full key never exists as a single Python object at runtime.

    Verification: all(key[i] == reduce(xor, [f[i] for f in frags]))
    """
    rng = random.Random(seed)
    frags = [[rng.randint(0, 255) for _ in key] for _ in range(n - 1)]
    last  = [key[i] for i in range(len(key))]
    for f in frags:
        for i in range(len(key)):
            last[i] ^= f[i]
    frags.append(last)
    return frags


def verify_split(key: list, frags: list) -> bool:
    """Verify that XOR of all fragments equals the original key."""
    reconstructed = [0] * len(key)
    for f in frags:
        for i in range(len(key)):
            reconstructed[i] ^= f[i]
    return reconstructed == list(key)
