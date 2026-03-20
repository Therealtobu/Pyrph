"""
ControlFlowFlattener (CFF)
Flattens function bodies into a state-machine dispatch loop with opaque guards.

Original:
    def f(x):
        if x > 0:
            return x
        return -x

After CFF:
    def f(x):
        __state = 0
        __result = None
        while True:
            if __state == 0:           # entry → branch
                if x > 0:
                    __state = 1
                else:
                    __state = 2
            elif __state == 1:         # true branch
                __result = x
                __state = 9999         # exit
            elif __state == 2:         # false branch
                __result = -x
                __state = 9999
            elif __state == 9999:
                return __result
            else:
                break
"""
import ast
import itertools
import random


_ctr = itertools.count(1)

EXIT_STATE = 9999


class _BlockCollector(ast.NodeVisitor):
    """Splits a function body into linear basic-blocks separated by jumps/ifs."""

    def __init__(self):
        self.blocks: list[list[ast.stmt]] = []
        self._current: list[ast.stmt] = []

    def _seal(self):
        if self._current:
            self.blocks.append(self._current)
            self._current = []

    def visit_If(self, node):
        self._seal()
        self.blocks.append([node])   # keep if as its own block

    def visit_For(self, node):
        self._seal()
        self.blocks.append([node])

    def visit_While(self, node):
        self._seal()
        self.blocks.append([node])

    def visit_Return(self, node):
        self._current.append(node)
        self._seal()

    def generic_visit(self, node):
        if isinstance(node, ast.stmt):
            self._current.append(node)
        else:
            super().generic_visit(node)

    def collect(self, stmts):
        for s in stmts:
            self.visit(s)
        self._seal()
        return self.blocks


class ControlFlowFlattener(ast.NodeTransformer):

    def transform(self, tree: ast.AST) -> ast.AST:
        return self.visit(tree)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        node.body = self._flatten(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    # ─────────────────────────────────────────────────────────────────────────
    def _flatten(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if len(body) <= 2:          # too small to be worth flattening
            return body

        collector = _BlockCollector()
        blocks = collector.collect(body)

        # Assign state IDs (randomised order to break linear reading)
        ids = list(range(len(blocks)))
        state_ids = [random.randint(0x10, 0xFFFE) for _ in ids]
        state_ids.append(EXIT_STATE)

        state_var   = f"__s{next(_ctr)}"
        result_var  = f"__r{next(_ctr)}"

        # Build elif chain:  if __state == id: <block> ; __state = next_id
        cases: list[ast.stmt] = []
        for i, (block, sid) in enumerate(zip(blocks, state_ids[:-1])):
            next_sid = state_ids[i + 1]

            # Replace any Return inside block with result assignment + exit
            block = self._patch_returns(block, result_var, EXIT_STATE, state_var)
            # Append state transition
            block.append(self._assign(state_var, next_sid))

            test = self._cmp_state(state_var, sid)
            cases.append((test, block))

        # Exit case
        exit_test  = self._cmp_state(state_var, EXIT_STATE)
        exit_block = [ast.Return(value=ast.Name(id=result_var, ctx=ast.Load()))]
        cases.append((exit_test, exit_block))

        # Build if/elif chain
        dispatch = self._build_dispatch(cases)

        loop = ast.While(
            test=ast.Constant(value=True),
            body=[dispatch, ast.Break()],
            orelse=[],
        )

        preamble = [
            self._assign(state_var, state_ids[0]),
            self._assign(result_var, None),
        ]
        return preamble + [loop]

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _assign(name: str, val) -> ast.Assign:
        node = ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=ast.Constant(value=val),
        )
        ast.fix_missing_locations(node)
        return node

    @staticmethod
    def _cmp_state(var: str, val: int) -> ast.expr:
        return ast.Compare(
            left=ast.Name(id=var, ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=val)],
        )

    @staticmethod
    def _build_dispatch(cases) -> ast.If:
        # Build from the end backwards
        node = ast.If(test=cases[-1][0], body=cases[-1][1], orelse=[ast.Break()])
        for test, block in reversed(cases[:-1]):
            node = ast.If(test=test, body=block, orelse=[node])
        ast.fix_missing_locations(node)
        return node

    def _patch_returns(self, stmts, result_var, exit_state, state_var):
        patched = []
        for s in stmts:
            if isinstance(s, ast.Return):
                val = s.value or ast.Constant(value=None)
                patched.append(ast.Assign(
                    targets=[ast.Name(id=result_var, ctx=ast.Store())],
                    value=val,
                ))
                patched.append(self._assign(state_var, exit_state))
                ast.fix_missing_locations(patched[-1])
                ast.fix_missing_locations(patched[-2])
            else:
                patched.append(s)
        return patched
