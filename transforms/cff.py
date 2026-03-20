"""
transforms/cff.py
==================
CFFPass — Control Flow Flattening.

Converts if/elif/else chains inside functions into a state-machine
dispatch loop with:
- Random non-sequential state IDs (0x1000–0xEFFF range)
- State variable initialised via XOR expression (not plaintext constant)
- 1–3 unreachable fake states injected and shuffled into the chain
- Each state transition also uses XOR expression

This makes the CFG unreadable to Ghidra/IDA's decompilers.
"""
from __future__ import annotations
import ast
import random
from ..core.base   import ObfPass
from ..core.result import ObfResult


def _rand_var() -> str:
    letters = "abcefghjkmnpqrtuvwxy"
    p1 = random.choice(letters); p2 = random.choice(letters)
    suffix = "".join(random.choices("abcdef0123456789" + letters, k=6))
    return f"_{p1}{p2}{suffix}"


def _xor_expr(val: int) -> ast.expr:
    a = random.randint(0x1000, 0xEFFF); b = a ^ val
    return ast.BinOp(left=ast.Constant(value=a),
                     op=ast.BitXor(),
                     right=ast.Constant(value=b))


def _assign(varname: str, val_expr: ast.expr) -> ast.Assign:
    node = ast.Assign(
        targets=[ast.Name(id=varname, ctx=ast.Store())],
        value=val_expr,
        lineno=1, col_offset=0,
    )
    ast.fix_missing_locations(node)
    return node


def _state_test(varname: str, val: int) -> ast.Compare:
    return ast.Compare(
        left=ast.Name(id=varname, ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=val)],
    )


class _CFFTransformer(ast.NodeTransformer):
    def __init__(self, n_fake: int):
        self.n_fake = n_fake
        self.count  = 0

    def _flatten(self, stmts: list) -> list:
        if not any(isinstance(s, ast.If) for s in stmts):
            return stmts

        sv = _rand_var()
        self.count += 1

        # Split into chunks at If boundaries
        chunks: list = [[]]
        for s in stmts:
            if isinstance(s, ast.If):
                chunks.append([s]); chunks.append([])
            else:
                chunks[-1].append(s)
        chunks = [c for c in chunks if c]

        n_real = len(chunks) + 1   # +1 for break state
        all_ids = random.sample(range(0x1000, 0xEFFF), n_real + self.n_fake)
        real_ids = all_ids[:n_real]
        fake_ids = all_ids[n_real:]

        cases: list = []

        # Real states
        for i, chunk in enumerate(chunks):
            next_id  = real_ids[i+1]
            set_next = _assign(sv, _xor_expr(next_id))
            body     = list(chunk) + [set_next]
            case     = ast.If(test=_state_test(sv, real_ids[i]),
                              body=body, orelse=[])
            cases.append(case)

        # Break state
        cases.append(ast.If(test=_state_test(sv, real_ids[-1]),
                            body=[ast.Break()], orelse=[]))

        # Fake (dead) states — jump back to first real state
        for fid in fake_ids:
            dead = ast.If(test=_state_test(sv, fid),
                          body=[_assign(sv, _xor_expr(real_ids[0]))],
                          orelse=[])
            cases.append(dead)

        # Shuffle fake states into random positions
        real_cases = cases[:len(chunks)+1]
        dead_cases = cases[len(chunks)+1:]
        random.shuffle(dead_cases)
        combined = list(real_cases)
        for dc in dead_cases:
            combined.insert(random.randint(0, len(combined)), dc)

        # Build elif chain
        def chain(cs):
            if not cs: return []
            first = cs[0]
            if cs[1:]: first.orelse = [chain(cs[1:])[0]]
            return [first]

        init = _assign(sv, _xor_expr(real_ids[0]))
        loop = ast.While(test=ast.Constant(value=True),
                         body=chain(combined), orelse=[])
        ast.fix_missing_locations(loop)
        return [init, loop]

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._flatten(node.body)
        return node
    visit_AsyncFunctionDef = visit_FunctionDef


class CFFPass(ObfPass):
    name        = "cff"
    phase       = 2
    description = "Flatten if/else into state-machine with random IDs + fake states"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)
        try:
            try: ast.parse(code)
            except SyntaxError as e: return self._err(code, e)
            n_fake = self.opts.get("n_fake_states", 2)
            tree   = ast.parse(code)
            t      = _CFFTransformer(n_fake)
            ast.fix_missing_locations(t.visit(tree))
            result = ast.unparse(tree)
            return self._ok(result,
                            message=f"flattened {t.count} function(s)",
                            count=t.count)
        except Exception as exc:
            return self._err(code, exc)
