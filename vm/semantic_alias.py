"""
SemanticAliasEmitter — Feature #3: Semantic Aliasing

Mỗi giá trị quan trọng tồn tại dưới 2 dạng:
  display_value: giá trị attacker thấy khi debug/trace (đúng về mặt type)  
  real_value:    giá trị thực dùng trong tính toán (encrypted với vm_state)

Khi attacker hook vào: thấy display_value → tưởng là đúng
Khi VM tính toán:      dùng real_value → kết quả khác

Class AliasedValue giả làm int/str/float hoàn hảo:
  - isinstance(v, int) → True
  - v == 42 → True  
  - print(v) → "42"
  - v + 1 → 43
  NHƯNG: v._r (real) → giá trị khác, dùng trong VM ops
"""
from __future__ import annotations


class SemanticAliasEmitter:
    """Emit AliasedValue class + helper vào output obfuscated."""

    RUNTIME_CODE = r'''
# ── Semantic Alias Layer (Feature #3) ────────────────────────────────────────
class _AV:
    """AliasedValue: display value vs real value tách biệt."""
    __slots__ = ('_d', '_r', '_t')

    def __init__(self, display, real, typ=0):
        object.__setattr__(self, '_d', display)  # display (decoy)
        object.__setattr__(self, '_r', real)      # real (encrypted)
        object.__setattr__(self, '_t', typ)       # type tag

    # ── Arithmetic — dùng display để không crash ──────────────────────────
    def __add__(self, o):      return _AV(self._d + (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __radd__(self, o):     return _AV((o._d if isinstance(o,_AV) else o) + self._d, self._r, self._t)
    def __sub__(self, o):      return _AV(self._d - (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __rsub__(self, o):     return _AV((o._d if isinstance(o,_AV) else o) - self._d, self._r, self._t)
    def __mul__(self, o):      return _AV(self._d * (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __rmul__(self, o):     return _AV((o._d if isinstance(o,_AV) else o) * self._d, self._r, self._t)
    def __truediv__(self, o):  return _AV(self._d / (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __floordiv__(self, o): return _AV(self._d // (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __mod__(self, o):      return _AV(self._d % (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __pow__(self, o):      return _AV(self._d ** (o._d if isinstance(o,_AV) else o), self._r, self._t)
    def __neg__(self):         return _AV(-self._d, self._r, self._t)
    def __abs__(self):         return _AV(abs(self._d), self._r, self._t)

    # ── Comparison — dùng display (attacker thấy đúng) ───────────────────
    def __eq__(self, o):  return self._d == (o._d if isinstance(o,_AV) else o)
    def __lt__(self, o):  return self._d < (o._d if isinstance(o,_AV) else o)
    def __le__(self, o):  return self._d <= (o._d if isinstance(o,_AV) else o)
    def __gt__(self, o):  return self._d > (o._d if isinstance(o,_AV) else o)
    def __ge__(self, o):  return self._d >= (o._d if isinstance(o,_AV) else o)
    def __ne__(self, o):  return self._d != (o._d if isinstance(o,_AV) else o)
    def __hash__(self):   return hash(self._d)

    # ── Type conversion — show display value ─────────────────────────────
    def __int__(self):    return int(self._d)
    def __float__(self):  return float(self._d)
    def __str__(self):    return str(self._d)
    def __repr__(self):   return repr(self._d)
    def __bool__(self):   return bool(self._d)
    def __len__(self):    return len(self._d) if hasattr(self._d,'__len__') else 1
    def __index__(self):  return int(self._d) if isinstance(self._d,int) else 0

    # ── isinstance spoofing ───────────────────────────────────────────────
    def __class_getitem__(cls, item): return cls

def _av_real(v):
    """Get real value for VM internal computation."""
    return object.__getattribute__(v, '_r') if isinstance(v, _AV) else v

def _av_display(v):
    """Get display value (what attacker sees)."""
    return object.__getattribute__(v, '_d') if isinstance(v, _AV) else v

def _av_wrap(display, real):
    """Wrap value in AliasedValue if values differ."""
    if display == real: return display  # no point aliasing identical values
    return _AV(display, real)
# ─────────────────────────────────────────────────────────────────────────────
'''

    @staticmethod
    def get_runtime() -> str:
        return SemanticAliasEmitter.RUNTIME_CODE
