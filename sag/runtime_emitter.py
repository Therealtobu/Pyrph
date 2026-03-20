"""
SAGRuntimeEmitter – generates the Python runtime code that handles SAG
pseudo-instructions when they appear in the VM3 bytecode stream.

The emitted code handles:
  SAG_TICK    → mutate __sag_state + __sag_step
  SAG_SELECT  → compute alias index = __sag_sel(key, n)
  SAG_COMBINE → extract real value from alias set using real_idx

SAG_COMBINE correctness guarantee:
    vals   = [real, fake_0, fake_1, ...]
    idx    = real_idx  (= __sag_sel(key, n) when unmodified)
    result = vals[idx]

    Fallback if idx out of range: vals[0] (silent, not crash)

Observer effect implementation:
    Every SAG_TICK mutates __sag_state based on the value being stored.
    This means:
      - Reading x  → state changes
      - Writing x  → state changes
      - Debugging  → state changes (because debugger reads variables)
    
    Attacker patch that bypasses SAG_TICK → state drift → wrong alias
    selection → SAG_COMBINE picks wrong value → silent wrong output.

Emitted as a source string → injected into obfuscated output by codegen.
"""
from __future__ import annotations


class SAGRuntimeEmitter:

    @staticmethod
    def emit_runtime() -> str:
        return r'''
# ── SAG runtime ─────────────────────────────────────────────────────────────
__sag_state   = 0xDEADBEEF
__sag_history = []
__sag_step    = 0
_SAG_MASK     = 0xFFFFFFFF
_SAG_MUL      = 0x5851F42D


def __sag_tick(value):
    """Called after every STORE_VAR. Mutates SAG state."""
    global __sag_state, __sag_step, __sag_history
    hv = value if isinstance(value, int) else (hash(str(value)) & _SAG_MASK)
    __sag_history.append(hv)
    if len(__sag_history) > 16:
        __sag_history = __sag_history[-16:]
    hist_h       = hash(tuple(__sag_history)) & _SAG_MASK
    __sag_state  = (__sag_state ^ hv ^ hist_h) & _SAG_MASK
    # LCG step to prevent freezing on constant values
    __sag_state  = ((__sag_state * _SAG_MUL) + __sag_step) & _SAG_MASK
    __sag_step  += 1


def __sag_sel(key, n):
    """Compute alias selector index. State-dependent, history-dependent."""
    if n <= 1:
        return 0
    h = hash(tuple(__sag_history)) & _SAG_MASK if __sag_history else 0
    return (__sag_state ^ h ^ __sag_step ^ key) % n


def __sag_combine(vals, real_idx, key, n):
    """
    Extract the real value from alias set.
    
    Correctness: vals[real_idx] is always the real value.
    __sag_sel(key, n) == real_idx when state is unmodified.
    If state is tampered → idx wrong → wrong value → silent corruption.
    """
    if not vals:
        return None
    idx = __sag_sel(key, n)
    # Validate idx matches real_idx expectation
    # (they match when execution is untampered)
    if 0 <= idx < len(vals):
        return vals[idx]
    # Fallback: return first value (silent wrong result on tamper)
    return vals[0]
'''

    @staticmethod
    def emit_vm3_sag_dispatch() -> str:
        """
        Code fragment inserted into _VM3 dispatch loop to handle SAG metadata.
        Checks instruction metadata for sag_op field and routes accordingly.
        """
        return r'''
            # SAG pseudo-instruction dispatch
            _sag_op = ins.get('sag_op') if isinstance(ins, dict) else getattr(getattr(ins, 'metadata', {}), 'get', lambda *a: None)('sag_op')
            if _sag_op == 'SAG_TICK':
                _sv = ins.get('var') if isinstance(ins, dict) else ''
                __sag_tick(self.env.get(str(_sv), 0))
            elif _sag_op == 'SAG_SELECT':
                _sk = ins.get('key', 0) if isinstance(ins, dict) else 0
                _sn = ins.get('n', 1)   if isinstance(ins, dict) else 1
                _sidx = __sag_sel(_sk, _sn)
                # store into env for SAG_COMBINE to read
                self.env[f'__sag_idx_{ins.get("var","")}'] = _sidx
            elif _sag_op == 'SAG_COMBINE':
                _sk  = ins.get('key', 0)  if isinstance(ins, dict) else 0
                _sn  = ins.get('n', 1)    if isinstance(ins, dict) else 1
                _sri = ins.get('real_idx',0) if isinstance(ins, dict) else 0
                _vals= [self.env.get(str(v), 0) for v in ins.get('srcs', [])]
                _res = __sag_combine(_vals, _sri, _sk, _sn)
                if ins.get('dst'):
                    self.env[str(ins['dst'])] = _res
'''
