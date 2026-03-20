"""
pyrph/key/hwid.py
==================
Collect a stable machine HWID.
"""
from __future__ import annotations
import hashlib
import platform
from pathlib import Path


def _machine_id() -> str:
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            return Path(p).read_text().strip()
        except Exception:
            pass
    return ""


def _cpu() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or ""


def get_hwid() -> str:
    parts = [_machine_id(), _cpu(), platform.machine(),
             f"{platform.python_version_tuple()[0]}.{platform.python_version_tuple()[1]}"]
    raw = "|".join(p for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
