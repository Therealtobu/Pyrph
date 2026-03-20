"""
transforms/string_vault.py
===========================
StringVaultPass — encrypt all string literals with a 16-byte rolling keystream.

Key strength:
- Each string has its own independent 16-byte key
- Keystream: K[j%16] ^ ((K[(j+3)%16]+j)&0xFF) ^ (K[(j+7)%16]*(j+1)&0xFF)
- Z3/symbolic solvers cannot recover key from a single output byte
- Custom base64 alphabet per-build (shuffled) — no standard b64 header

Runtime structure:
    _VD = "custom-b64-encoded blob"       # all strings concatenated + encrypted
    _VK = [[16 bytes], ...]               # one key list per string
    _VO = [offset, ...]                   # byte offsets into _VD
    _VL = [length, ...]                   # byte lengths
    _VC = {}                              # lazy decode cache

    def _V(i):
        if i not in _VC:
            _raw = decode(_VD)
            _k   = _VK[i]
            _VC[i] = bytes(
                _x^(_k[_j%16]^((_k[(_j+3)%16]+_j)&0xFF)^(_k[(_j+7)%16]*(_j+1)&0xFF))&0xFF
                for _j,_x in enumerate(_raw[_VO[i]:_VO[i]+_VL[i]])
            ).decode('utf-8', errors='replace')
        return _VC[i]
"""
from __future__ import annotations
import ast
import base64
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _make_alphabet(seed: int):
    rng  = random.Random(seed)
    enc  = list(_STD); rng.shuffle(enc)
    return "".join(enc)


def _custom_b64encode(data: bytes, enc_alph: str) -> str:
    standard = base64.b64encode(data).decode("ascii")
    return standard.translate(str.maketrans(_STD, enc_alph))


def _ks_byte(key: list, j: int) -> int:
    return (key[j%16] ^ ((key[(j+3)%16]+j)&0xFF) ^ (key[(j+7)%16]*(j+1)&0xFF)) & 0xFF


def _encrypt(data: bytes, key: list) -> bytes:
    return bytes(b ^ _ks_byte(key, j) for j,b in enumerate(data))


def _is_docstring(node, parent_body) -> bool:
    if not parent_body: return False
    first = parent_body[0]
    return (isinstance(first, ast.Expr) and
            isinstance(first.value, ast.Constant) and
            isinstance(first.value.value, str) and first is node)


def _rand_name(n=6) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices("abcdef0123456789", k=n))
    pos = random.randint(0, n-1)
    return "_" + raw[:pos] + random.choice(letters) + raw[pos:]


class _VaultTransformer(ast.NodeTransformer):
    def __init__(self, fn_name: str, min_len: int):
        self.fn_name = fn_name
        self.min_len = min_len
        self.strings: list = []
        self._pbody:  list = []

    def _collect(self, s: str) -> ast.expr:
        idx = len(self.strings)
        self.strings.append(s)
        return ast.Call(func=ast.Name(id=self.fn_name, ctx=ast.Load()),
                        args=[ast.Constant(value=idx)], keywords=[])

    def _visit_body(self, body):
        old = self._pbody; self._pbody = body
        new = [self.visit(s) for s in body]
        self._pbody = old; return new

    def visit_Module(self, node):
        node.body = self._visit_body(node.body); return node

    def visit_FunctionDef(self, node):
        node.body = self._visit_body(node.body); return node
    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef         = visit_FunctionDef

    def visit_Constant(self, node):
        if not isinstance(node.value, str): return node
        if len(node.value) < self.min_len:  return node
        if _is_docstring(node, self._pbody): return node
        return self._collect(node.value)

    def visit_JoinedStr(self, node): return node


class StringVaultPass(ObfPass):
    name        = "string_vault"
    phase       = 1
    description = "Encrypt string literals with 16-byte keystream + custom b64"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            min_len = self.opts.get("min_len", 3)
            fn_name = _rand_name(7)
            seed    = random.randint(0, 0xFFFFFFFF)

            tree = ast.parse(code)
            t    = _VaultTransformer(fn_name=fn_name, min_len=min_len)
            t.visit(tree)
            ast.fix_missing_locations(tree)

            if not t.strings:
                return self._ok(code, message="no strings vaulted")

            keys     = [[random.randint(0,255) for _ in range(16)] for _ in t.strings]
            enc_alph = _make_alphabet(seed)

            parts   = []; offsets = []; lengths = []; pos = 0
            for s, k in zip(t.strings, keys):
                raw = s.encode("utf-8")
                enc = _encrypt(raw, k)
                offsets.append(pos); lengths.append(len(enc))
                parts.append(enc);   pos += len(enc)

            blob     = b"".join(parts)
            blob_enc = _custom_b64encode(blob, enc_alph)

            def _esc(s):
                return s.replace("\\","\\\\").replace("'","\\'")

            vD = _rand_name(5); vK = _rand_name(5)
            vO = _rand_name(5); vL = _rand_name(5)
            vC = _rand_name(5)

            decode_expr = (
                f"__import__('base64').b64decode("
                f"{vD}.translate(str.maketrans('{_esc(enc_alph)}','{_esc(_STD)}')))"
            )

            header = (
                f"{vD}={repr(blob_enc)}\n"
                f"{vK}={repr(keys)}\n"
                f"{vO}={repr(offsets)}\n"
                f"{vL}={repr(lengths)}\n"
                f"{vC}={{}}\n"
                f"def {fn_name}(_i):\n"
                f"    if _i not in {vC}:\n"
                f"        _raw={decode_expr}\n"
                f"        _k={vK}[_i]\n"
                f"        {vC}[_i]=bytes(\n"
                f"            _x^(_k[_j%16]^((_k[(_j+3)%16]+_j)&0xFF)^(_k[(_j+7)%16]*(_j+1)&0xFF))&0xFF\n"
                f"            for _j,_x in enumerate(_raw[{vO}[_i]:{vO}[_i]+{vL}[_i]])\n"
                f"        ).decode('utf-8',errors='replace')\n"
                f"    return {vC}[_i]\n"
            )

            result = header + "\n" + ast.unparse(tree)
            return self._ok(result,
                            message=f"vaulted {len(t.strings)} string(s)",
                            count=len(t.strings))
        except Exception as exc:
            return self._err(code, exc)
