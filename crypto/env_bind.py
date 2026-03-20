"""
crypto/env_bind.py
===================
Environment-bound key generation — machine-locked protection.

When env_bind is enabled, the AES key is derived by mixing a base key
with fingerprints from the target execution environment:

  final_key = HMAC-SHA256(base_key, machine_fingerprint)

This means the obfuscated file will ONLY run on the machine it was
obfuscated for, or machines with matching fingerprints.

Fingerprint sources (configurable):
  - /etc/machine-id           (Linux unique machine ID)
  - /var/lib/dbus/machine-id  (fallback)
  - Python version string
  - Platform architecture
  - CPU model (via /proc/cpuinfo on Linux)
  - Hostname

The C runtime reconstructs the fingerprint at runtime and verifies
that HMAC-SHA256(baked_key, runtime_fingerprint) == expected_key.
If the fingerprint doesn't match, decryption produces garbage silently
(no error that reveals why it failed).
"""
from __future__ import annotations
import hashlib
import hmac
import os
import platform
import socket
from pathlib import Path


# ── Fingerprint collection ────────────────────────────────────────────────

def _read_machine_id() -> str:
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            return Path(path).read_text().strip()
        except Exception:
            pass
    return ""


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def collect_fingerprint(sources: list = None) -> bytes:
    """
    Collect machine fingerprint from the specified sources.

    Parameters
    ----------
    sources : list of strings, any of:
        "machine_id"  — /etc/machine-id
        "python"      — Python version
        "platform"    — OS platform string
        "arch"        — CPU architecture
        "hostname"    — machine hostname
        "cpu"         — CPU model (/proc/cpuinfo)

    Returns
    -------
    32-byte SHA-256 fingerprint
    """
    if sources is None:
        sources = ["machine_id", "python", "arch"]

    parts = []
    for src in sources:
        if src == "machine_id":
            parts.append(_read_machine_id())
        elif src == "python":
            parts.append(platform.python_version())
        elif src == "platform":
            parts.append(platform.platform())
        elif src == "arch":
            parts.append(platform.machine())
        elif src == "hostname":
            try:
                parts.append(socket.gethostname())
            except Exception:
                parts.append("")
        elif src == "cpu":
            parts.append(_cpu_model())

    material = "|".join(parts).encode("utf-8")
    return hashlib.sha256(material).digest()


# ── Key binding ───────────────────────────────────────────────────────────

def bind_key(base_key: bytes, fingerprint: bytes) -> bytes:
    """
    Derive an environment-bound key.
    final_key = HMAC-SHA256(base_key, fingerprint)[:16]
    """
    bound = hmac.new(base_key, fingerprint, hashlib.sha256).digest()
    # Ensure non-zero bytes
    key = bytearray(bound[:16])
    for i in range(16):
        if key[i] == 0:
            key[i] = (bound[i + 16] % 254) + 1
    return bytes(key)


def make_bound_key(base_key: bytes, sources: list = None) -> tuple:
    """
    Create an environment-bound key for the current machine.

    Returns
    -------
    (bound_key, fingerprint_bytes, sources_used)

    bound_key is what gets baked into the .so.
    fingerprint + sources are stored in the launcher for runtime verification.
    """
    sources       = sources or ["machine_id", "python", "arch"]
    fingerprint   = collect_fingerprint(sources)
    bound_key     = bind_key(base_key, fingerprint)
    return bound_key, fingerprint, sources


def gen_runtime_verify_code(fingerprint: bytes, sources: list,
                             fail_silent: bool = True) -> str:
    """
    Generate Python code that re-collects the fingerprint at runtime
    and raises an error (or silently corrupts) if it doesn't match.

    This code is injected into the launcher .py.
    """
    import random
    vfp  = "_fp" + "".join(random.choices("abcdef0123456789", k=6))
    vexp = "_ex" + "".join(random.choices("abcdef0123456789", k=6))

    fp_hex = fingerprint.hex()

    lines = [
        f"import hashlib as _hs, platform as _pf",
        f"def _collect_fp():",
        f"    _p=[]",
    ]
    for src in sources:
        if src == "machine_id":
            lines += [
                f"    try:",
                f"        for _mf in ['/etc/machine-id','/var/lib/dbus/machine-id']:",
                f"            try: _p.append(open(_mf).read().strip()); break",
                f"            except: pass",
                f"    except: _p.append('')",
            ]
        elif src == "python":
            lines.append(f"    _p.append(_pf.python_version())")
        elif src == "arch":
            lines.append(f"    _p.append(_pf.machine())")
        elif src == "platform":
            lines.append(f"    _p.append(_pf.platform())")
        elif src == "hostname":
            lines += [
                f"    try: import socket; _p.append(socket.gethostname())",
                f"    except: _p.append('')",
            ]

    lines += [
        f"    return _hs.sha256('|'.join(_p).encode()).digest()",
        f"{vfp}=_collect_fp()",
        f"{vexp}=bytes.fromhex('{fp_hex}')",
    ]

    if fail_silent:
        # Corrupt a global sentinel — downstream code will fail mysteriously
        lines += [
            f"if {vfp}!={vexp}:",
            f"    import sys; sys.modules[__name__] = None  # silent corruption",
        ]
    else:
        lines += [
            f"if {vfp}!={vexp}:",
            f"    raise ImportError('invalid environment')",
        ]

    return "\n".join(lines) + "\n"
