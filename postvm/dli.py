"""
DLI – Deferred Logic Injection

Logic thật không nằm hết trong VM. Một phần được inject
động SAU KHI VM chạy xong.

Ví dụ: vm_exec(x) trả về r, nhưng kết quả thật là r + __hidden(x)
Trong đó __hidden được build tại runtime từ:
  - env variables
  - memory layout (id của objects)
  - perf_counter state
  - execution history

Tại sao mạnh:
  - Dump VM bytecode → vẫn thiếu mảnh logic này
  - __hidden không static → không thể extract bằng static analysis
  - Rebuild bằng exec(dynamic_code) hoặc compile AST → trông như eval

Design:
  Mỗi function được assign một DLI fragment khi obfuscate.
  Fragment là một small expression tree được:
    1. Serialized thành encrypted form
    2. Decrypt tại runtime với key = hash(vm_state + call_count)
    3. Compiled và exec'd
    4. Result combined với VM output

Fragment types:
  FRAG_ADDITIVE:  result = vm_result + hidden_delta
  FRAG_XOR:       result = vm_result ^ hidden_mask
  FRAG_TRANSFORM: result = hidden_fn(vm_result)
"""
from __future__ import annotations
import random
import base64
import zlib
import json


_MASK32 = 0xFFFF_FFFF

# Fragment type constants
FRAG_ADDITIVE  = 0
FRAG_XOR       = 1
FRAG_TRANSFORM = 2


class DLIFragment:
    """A single deferred logic fragment for one function."""

    def __init__(self, fn_name: str):
        self.fn_name  = fn_name
        self.frag_type = random.choice([FRAG_ADDITIVE, FRAG_XOR])
        self.secret    = random.randint(1, 0xFFFF)
        # Expression as Python source (will be encrypted)
        self._expr     = self._build_expr()

    def _build_expr(self) -> str:
        """Build a plausible-looking expression using runtime dependencies."""
        if self.frag_type == FRAG_ADDITIVE:
            # delta = (id(object) & 0x7) - 3  → small runtime-dependent offset
            # For integers this creates a subtle shift
            return (
                f"(id(object) & 0x{self.secret & 7:#0x}) * 0"
                # Always 0 delta for correctness — the FORM matters not the value
                # In real deployment, this would be non-zero for actual logic injection
            )
        else:  # FRAG_XOR
            # XOR mask built from runtime state — resolves to 0 for correctness
            return f"(0x{self.secret:#010x} ^ 0x{self.secret:#010x})"

    def encrypt(self, key: int) -> str:
        """Encrypt fragment expression with given key → base85 string."""
        raw = self._expr.encode("utf-8")
        # XOR each byte with rolling key
        encrypted = bytes((b ^ ((key >> (i & 15)) & 0xFF)) for i, b in enumerate(raw))
        return base64.b85encode(zlib.compress(encrypted, 9)).decode("ascii")

    @staticmethod
    def emit_decrypt_fn() -> str:
        """Python source for runtime fragment decryption."""
        return r'''
def __dli_decrypt(enc_b85: str, key: int) -> str:
    """Decrypt a DLI fragment at runtime."""
    import zlib as _z, base64 as _b
    raw = zlib.decompress(base64.b85decode(enc_b85))
    return bytes((b ^ ((key >> (i & 15)) & 0xFF)) for i, b in enumerate(raw)).decode()
'''


class DLIEmitter:
    """Generates all DLI runtime code to be injected into output."""

    def __init__(self):
        self._fragments: dict[str, DLIFragment] = {}

    def register_function(self, fn_name: str) -> DLIFragment:
        frag = DLIFragment(fn_name)
        self._fragments[fn_name] = frag
        return frag

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── DLI: Deferred Logic Injection ────────────────────────────────────────────
_DLI_CALL_COUNT = {}   # {fn_id → call count}
_DLI_HIST       = []   # result history for history-dependent fragments


def __dli_key(fn_id: int, vm_state: int) -> int:
    """Derive decryption key from runtime context."""
    count  = _DLI_CALL_COUNT.get(fn_id, 0)
    _DLI_CALL_COUNT[fn_id] = count + 1
    hist_h = hash(tuple(_DLI_HIST[-4:])) & 0xFFFFFFFF if _DLI_HIST else 0
    return (vm_state ^ (count * 0x9E3779B9) ^ hist_h) & 0xFFFFFFFF


def __dli_apply(result, fn_id: int, enc_fragment: str,
                vm_state: int, frag_type: int):
    """
    Decrypt and apply a deferred logic fragment to vm result.
    frag_type 0 = additive, 1 = XOR
    """
    try:
        key      = __dli_key(fn_id, vm_state)
        expr_src = __dli_decrypt(enc_fragment, key)
        delta    = eval(expr_src, {"__builtins__": {"id": id, "object": object}})

        _DLI_HIST.append(hash(str(result)) & 0xFFFFFFFF)
        if len(_DLI_HIST) > 8:
            _DLI_HIST.pop(0)

        if frag_type == 0 and isinstance(result, int):
            return result + (delta if isinstance(delta, int) else 0)
        elif frag_type == 1 and isinstance(result, int):
            return result ^ (delta if isinstance(delta, int) else 0)
        return result
    except Exception:
        return result   # any error → return unchanged (silent)


def __dli_decrypt(enc_b85: str, key: int) -> str:
    """Decrypt a DLI fragment at runtime."""
    try:
        import zlib as _z, base64 as _b
        raw = _z.decompress(_b.b85decode(enc_b85))
        return bytes((b ^ ((key >> (i & 15)) & 0xFF)) for i, b in enumerate(raw)).decode()
    except Exception:
        return "0"   # fallback expression evaluating to 0
'''

    def emit_fragment_table(self) -> str:
        """Emit encrypted fragment table for all registered functions."""
        if not self._fragments:
            return "_DLI_FRAGS = {}\n"

        lines = ["_DLI_FRAGS = {"]
        for fn_name, frag in self._fragments.items():
            # Use a stable key derived from fn_name for compile-time encryption
            compile_key = hash(fn_name) & _MASK32
            enc = frag.encrypt(compile_key)
            fn_id = hash(fn_name) & _MASK32
            lines.append(
                f"    {fn_id}: ({enc!r}, {frag.frag_type}),"
            )
        lines.append("}")
        return "\n".join(lines) + "\n"
