"""
native/builder.py
==================
Compile runtime.c → _pyrph.so.

Per-build compilation (no caching) so every output .py has a unique .so.
Tries clang first (LLVM IR passes if available), falls back to gcc.

v2 features:
- Whitebox AES key injection via generated header file
- LLVM instruction substitution (-mllvm -sub) if available
- Per-build unique binary (SelfMutate via ELF padding randomisation)
- Compiler flags: -O2 -s -fvisibility=hidden -fstack-protector-strong
"""
from __future__ import annotations
import base64
import os
import random
import subprocess
import sys
import sysconfig
from pathlib import Path

from . import wb_aes

_HERE   = Path(__file__).parent
_SRC    = _HERE / "runtime.c"
_WB_HDR = _HERE / "_wb_key.h"


# ── AES key ───────────────────────────────────────────────────────────────

def _random_key() -> bytes:
    return bytes(random.randint(1, 254) for _ in range(16))


# ── WB header ─────────────────────────────────────────────────────────────

def _write_wb_header(aes_key: bytes, rng: random.Random) -> None:
    kd, kp, km = wb_aes.generate(aes_key, rng)
    assert wb_aes.verify(aes_key, kd, kp, km)
    _WB_HDR.write_text(wb_aes.to_c_header(kd, kp, km))


# ── Compiler detection ─────────────────────────────────────────────────────

def _has(cmd: list) -> bool:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False

def _has_clang()  -> bool: return _has(["clang", "--version"])
def _has_gcc()    -> bool: return _has(["gcc",   "--version"])

def _has_llvm_sub() -> bool:
    try:
        r = subprocess.run(
            ["clang", "-mllvm", "-sub", "-x", "c", "-", "-o", "/dev/null"],
            input=b"int main(){return 0;}",
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── ELF self-mutate ────────────────────────────────────────────────────────

def _mutate_elf(data: bytes, rng: random.Random) -> bytes:
    """Randomise ELF padding + build-id to produce unique fingerprint."""
    import struct
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return data
    mutated = bytearray(data)
    try:
        e_shoff, e_shentsize, e_shnum = struct.unpack_from("<QHH", data, 0x28)
        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_type, _, _, sh_offset, sh_size = struct.unpack_from("<II QQQ", data, off+4)
            if sh_type != 0 and sh_offset and sh_size:
                sections.append((sh_offset, sh_size))
        sections.sort()
        for i in range(len(sections)-1):
            end = sections[i][0]+sections[i][1]; start = sections[i+1][0]
            if start > end and all(b==0 for b in data[end:start]):
                for j in range(end, start):
                    mutated[j] = rng.randint(1,255)
    except Exception:
        pass
    marker = b"GNU\x00\x14\x00\x00\x00\x03\x00\x00\x00"
    idx = data.find(marker)
    if idx != -1:
        off = idx + len(marker)
        for i in range(min(20, len(data)-off)):
            mutated[off+i] = rng.randint(0,255)
    return bytes(mutated)


# ── Build ──────────────────────────────────────────────────────────────────

def build(aes_key: bytes = None,
          seed: int = None) -> tuple:
    """
    Compile runtime.c and return (so_bytes, aes_key_used).
    Always produces a fresh unique build.
    """
    if aes_key is None:
        aes_key = _random_key()

    rng = random.Random(seed)
    _write_wb_header(aes_key, rng)

    pyinc  = sysconfig.get_path("include")
    pylib  = sysconfig.get_config_var("LIBDIR") or ""
    ver    = f"{sys.version_info.major}.{sys.version_info.minor}"
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    out    = _HERE / f"_pyrph_build{suffix}"

    use_clang = _has_clang()
    use_sub   = use_clang and _has_llvm_sub()

    compiler = "clang" if use_clang else "gcc"
    flags    = [
        "-shared", "-fPIC", "-O2", "-s",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-fno-asynchronous-unwind-tables",
        f"-include{_WB_HDR}",
        "-DPYRPH_V2=1",
        "-o", str(out),
        str(_SRC),
        f"-I{pyinc}",
        "-Wno-unused-result",
        "-Wno-pointer-sign",
        "-Wl,--strip-all",
    ]
    if use_sub:
        flags = [compiler, "-mllvm", "-sub", "-mllvm", "-sub_loop=2"] + flags
    else:
        flags = [compiler] + flags

    libpython = os.path.join(pylib, f"libpython{ver}.so")
    if os.path.exists(libpython):
        flags += [f"-L{pylib}", f"-lpython{ver}"]

    result = subprocess.run(flags, capture_output=True, text=True)
    if result.returncode != 0:
        # retry without LLVM flags
        if use_sub:
            flags2 = ["clang"] + flags[3:]
            result = subprocess.run(flags2, capture_output=True, text=True)
        # fallback gcc
        if result.returncode != 0:
            flags3 = ["gcc"] + [f for f in flags[1:] if not f.startswith("-mllvm")]
            result = subprocess.run(flags3, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Native compile failed:\n{result.stderr}"
                )

    so_bytes = out.read_bytes()
    so_bytes = _mutate_elf(so_bytes, rng)

    try: out.unlink()
    except Exception: pass
    try: _WB_HDR.unlink()
    except Exception: pass

    return so_bytes, aes_key


def build_b64(seed: int = None) -> tuple:
    """Return (base64_str, aes_key)."""
    so, key = build(seed=seed)
    return base64.b64encode(so).decode("ascii"), key


def is_available() -> bool:
    if not (_has_gcc() or _has_clang()):
        return False
    pyinc = sysconfig.get_path("include")
    return (Path(pyinc) / "Python.h").exists()
