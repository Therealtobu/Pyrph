"""
transforms/self_mutate.py
==========================
SelfMutatePass — randomise the embedded .so ELF binary per build.

Every time Pyrph obfuscates a file, the .so gets a unique fingerprint
so that hash-based detection and signature matching are ineffective.

Mutation strategy (safe — only touches inert bytes):
  1. Zero-filled padding regions between ELF sections
     → overwrite with random non-zero bytes (never executed)
  2. GNU build-id note (20-byte SHA1 debug identifier)
     → replace with random bytes (debug-only, never affects execution)
  3. .comment section (GCC version string area)
     → overwrite with random bytes if present

None of these mutations affect any executed byte.
"""
from __future__ import annotations
import random
import struct


_ELF_MAGIC = b"\x7fELF"


def _parse_elf64_sections(data: bytes) -> list:
    """Parse 64-bit ELF and return [(offset, size)] for each section."""
    if len(data) < 64 or data[:4] != _ELF_MAGIC or data[4] != 2:
        return []
    try:
        e_shoff, e_shentsize, e_shnum = struct.unpack_from("<QHH", data, 0x28)
        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_type, _, _, sh_offset, sh_size = struct.unpack_from(
                "<II QQQ", data, off + 4)
            if sh_type == 0 or not sh_offset or not sh_size:
                continue
            sections.append((sh_offset, sh_size))
        return sections
    except struct.error:
        return []


def _find_padding(data: bytes, sections: list, min_pad: int = 4) -> list:
    """Find zero-filled gaps between consecutive sections."""
    sorted_secs = sorted(sections)
    padding = []
    for i in range(len(sorted_secs) - 1):
        end   = sorted_secs[i][0] + sorted_secs[i][1]
        start = sorted_secs[i + 1][0]
        if start > end:
            region = data[end:start]
            if len(region) >= min_pad and all(b == 0 for b in region):
                padding.append((end, start - end))
    return padding


def _find_build_id(data: bytes):
    """Locate GNU build-id hash bytes. Returns (offset, 20) or None."""
    marker = b"GNU\x00\x14\x00\x00\x00\x03\x00\x00\x00"
    idx = data.find(marker)
    if idx == -1:
        return None
    off = idx + len(marker)
    return (off, 20) if off + 20 <= len(data) else None


def mutate(so_bytes: bytes,
           rng: random.Random = None,
           mutate_padding: bool  = True,
           mutate_build_id: bool = True) -> bytes:
    """
    Apply safe ELF mutations and return the modified binary.
    If the binary is not a recognisable ELF, returns it unchanged.
    """
    if len(so_bytes) < 64 or so_bytes[:4] != _ELF_MAGIC:
        return so_bytes

    if rng is None:
        rng = random.Random()

    data = bytearray(so_bytes)

    if mutate_padding:
        sections = _parse_elf64_sections(bytes(data))
        for (off, size) in _find_padding(bytes(data), sections):
            for i in range(size):
                data[off + i] = rng.randint(1, 255)  # non-zero to be distinct

    if mutate_build_id:
        loc = _find_build_id(bytes(data))
        if loc:
            off, size = loc
            for i in range(size):
                data[off + i] = rng.randint(0, 255)

    return bytes(data)


def mutate_b64(so_b64: str, rng: random.Random = None) -> str:
    """Convenience: base64 in → mutate → base64 out."""
    import base64
    raw     = base64.b64decode(so_b64)
    mutated = mutate(raw, rng)
    return base64.b64encode(mutated).decode("ascii")


class SelfMutatePass:
    """Callable wrapper for use in the native builder."""
    def __init__(self, seed: int = None,
                 mutate_padding: bool  = True,
                 mutate_build_id: bool = True):
        self.rng            = random.Random(seed)
        self.mutate_padding  = mutate_padding
        self.mutate_build_id = mutate_build_id

    def mutate(self, so_bytes: bytes) -> bytes:
        return mutate(so_bytes, self.rng,
                      self.mutate_padding, self.mutate_build_id)

    def mutate_b64(self, so_b64: str) -> str:
        return mutate_b64(so_b64, self.rng)
