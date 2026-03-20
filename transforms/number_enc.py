"""
transforms/number_enc.py
=========================
NumberEncPass — replace integer literals with opaque arithmetic expressions.

Encoding schemes (randomly chosen per number):
  n → (a ^ b)          XOR split
  n → (a + b)          ADD split
  n → (a | b)          OR split  (non-overlapping bits)
  n → ((n<<s)>>s)      shift roundtrip
  n → (~(~n))          double invert
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _xor_split(n: int) -> str:
    a = random.randint(0, 0xFFFF); b = a ^ n
    return f"({a}^{b})"

def _add_split(n: int) -> str:
    a = random.randint(0, abs(n)+1000); b = n - a
    return f"({a}+{b})" if b >= 0 else f"({a}-{abs(b)})"

def _shift_rt(n: int) -> str:
    if n <= 0: return None
    s = random.randint(1, 4)
    return f"(({n}<<{s})>>{s})"

def _or_split(n: int) -> str:
    if n <= 0: return None
    bits = n.bit_length(); split = random.randint(1, bits)
    mask = (1<<split)-1; a = n&mask; b = n&~mask
    if (a|b)==n and (a&b)==0: return f"({a}|{b})"
    return None

def _double_inv(n: int) -> str:
    return f"(~~{n})" if n >= 0 else None

def _encode(n: int) -> str:
    if abs(n) > 0x7FFFFFFF: return str(n)
    schemes = [_xor_split, _add_split]
    if n > 0: schemes += [_shift_rt, _or_split, _double_inv]
    random.shuffle(schemes)
    for fn in schemes:
        try:
            r = fn(n)
            if r and eval(r) == n:  # noqa: S307
                return r
        except Exception:
            continue
    return str(n)


class _NumTransformer(ast.NodeTransformer):
    def __init__(self, density: float):
        self.density = density; self.count = 0

    def visit_Constant(self, node):
        if (isinstance(node.value, int) and
                not isinstance(node.value, bool) and
                abs(node.value) > 1 and
                random.random() < self.density):
            expr = _encode(node.value)
            if expr != str(node.value):
                try:
                    new = ast.parse(expr, mode='eval').body
                    ast.copy_location(new, node)
                    ast.fix_missing_locations(new)
                    self.count += 1
                    return new
                except Exception:
                    pass
        return node


class NumberEncPass(ObfPass):
    name        = "number_enc"
    phase       = 1
    description = "Encode integer literals as opaque XOR/ADD/OR expressions"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            density = self.opts.get("density", 0.85)
            tree    = ast.parse(code)
            t       = _NumTransformer(density)
            ast.fix_missing_locations(t.visit(tree))
            return self._ok(ast.unparse(tree),
                            message=f"encoded {t.count} integer(s)",
                            count=t.count)
        except Exception as exc:
            return self._err(code, exc)
