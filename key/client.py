"""
pyrph/key/client.py
====================
Key verification client — talks to Pyrph API.
Caches result locally for 10 minutes.
"""
from __future__ import annotations
import hashlib, json, os, time
from pathlib import Path
from typing import Optional

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .hwid import get_hwid

API_BASE   = os.environ.get("PYRPH_API", "https://pyrph-api.up.railway.app")
CONFIG_DIR = Path.home() / ".pyrph"
KEY_FILE   = CONFIG_DIR / "key.txt"
CACHE_FILE = CONFIG_DIR / "cache.json"
CACHE_TTL  = 600   # 10 minutes

TIER_FEATURES = {
    "free": {
        "profiles":   ["fast", "balanced"],
        "native":     False,
        "nested_vm":  False,
        "poly_vm":    True,
        "one_shot":   True,    # expires after 1 use
    },
    "paid": {
        "profiles":   ["fast", "balanced", "max", "stealth", "vm", "vm_max"],
        "native":     True,
        "nested_vm":  True,
        "poly_vm":    True,
        "one_shot":   False,
    },
}


# ── Cache ─────────────────────────────────────────────────────────────────

def _load_cache() -> Optional[dict]:
    try:
        d = json.loads(CACHE_FILE.read_text())
        if time.time() - d.get("ts", 0) < CACHE_TTL:
            return d
    except Exception:
        pass
    return None


def _save_cache(data: dict):
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        d = dict(data); d["ts"] = time.time()
        CACHE_FILE.write_text(json.dumps(d))
    except Exception:
        pass


def _clear_cache():
    try: CACHE_FILE.unlink()
    except Exception: pass


# ── Key storage ───────────────────────────────────────────────────────────

def load_key() -> Optional[str]:
    try: return KEY_FILE.read_text().strip()
    except Exception: return None


def save_key(key: str):
    CONFIG_DIR.mkdir(exist_ok=True)
    KEY_FILE.write_text(key.strip())
    _clear_cache()


def delete_key():
    try: KEY_FILE.unlink()
    except Exception: pass
    _clear_cache()


# ── API calls ─────────────────────────────────────────────────────────────

def _post(endpoint: str, payload: dict) -> dict:
    if not _HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=8)
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "offline"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def verify(key: Optional[str] = None) -> dict:
    """
    Verify key + HWID with server.
    Returns: {ok, tier, features, error, expires_at}
    """
    if not key:
        key = os.environ.get("PYRPH_KEY") or load_key()
    if not key:
        return {"ok": False, "tier": None, "features": None, "error": "no_key"}

    # Cache check
    cache = _load_cache()
    kh = hashlib.sha256(key.encode()).hexdigest()
    if cache and cache.get("kh") == kh:
        return cache

    hwid = get_hwid()
    data = _post("/api/verify", {"key": key, "hwid": hwid})

    if data.get("ok"):
        data["kh"] = kh
        _save_cache(data)

    return data


def getkey_request(hwid: str) -> dict:
    """Ask server for a free key for this HWID."""
    return _post("/api/getkey", {"hwid": hwid})


def activate(key: str) -> dict:
    """Activate (bind) a key to this machine's HWID."""
    hwid = get_hwid()
    data = _post("/api/activate", {"key": key, "hwid": hwid})
    if data.get("ok"):
        save_key(key)
        _clear_cache()
    return data


def mark_used(key: str):
    """Mark a free key as used (one-shot expiry)."""
    hwid = get_hwid()
    _post("/api/mark_used", {"key": key, "hwid": hwid})
    _clear_cache()
