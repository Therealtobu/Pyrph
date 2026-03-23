"""
MetamorphicDispatcher – tạo dispatch wrapper function cho N variants.

Dispatch logic:
    vid = (hash((session_key, arg0, arg1, ...)) ^ call_counter) % N

session_key:
    - Generated once at module startup: random.getrandbits(64)
    - Không predictable → cùng args nhưng different run → different variant
    - Tuy nhiên: cùng run + cùng args + cùng call_counter → same variant
      (deterministic within one execution → correct output)

call_counter:
    - Increments per call to this function
    - Prevents "always same args → always same variant"
    - Adds temporal variation: call 1 vs call 2 với same args → different variant

IR-level: emit một CALL_DISPATCH instruction thay cho CALL trực tiếp.
Codegen sẽ emit Python wrapper code cho dispatch.

Cấu trúc emitted:
    __mm_key = random.getrandbits(64)         # module level
    __mm_ctr = {}                             # per-function call counters

    def foo__var0(a, b): ...                  # variant 0
    def foo__var1(a, b): ...                  # variant 1
    def foo__var2(a, b): ...                  # variant 2

    def foo(a, b):                            # dispatcher
        _ctr = __mm_ctr.get('foo', 0)
        __mm_ctr['foo'] = _ctr + 1
        _vid = (hash((__mm_key, a, b)) ^ _ctr) % 3
        return [foo__var0, foo__var1, foo__var2][_vid](a, b)
"""
from __future__ import annotations
from ..ir.nodes import IROp, IROperand, IRInstruction, IRFunction, IRModule

_VAR   = lambda n: IROperand("var",   n)
_CONST = lambda v: IROperand("const", v)
_REG   = lambda n: IROperand("reg",   n)


class MetamorphicDispatcher:
    """
    Inject dispatch function IR for each set of variants.
    Also tracks which original functions have been metamorphized.
    """

    def __init__(self):
        self._dispatched: set[str] = set()

    def build_dispatcher(self,
                         original_fn: IRFunction,
                         variants: list[IRFunction],
                         module: IRModule) -> IRFunction:
        """
        Build a dispatcher IRFunction that:
          1. computes variant_id from hash(session_key, args)
          2. calls the selected variant
          3. returns its result
        """
        n    = len(variants)
        name = original_fn.name
        args = original_fn.args

        dispatch_fn = IRFunction(name=name, args=args)
        entry       = dispatch_fn.new_block("dispatch_entry")

        # Emit:
        #   t_key  = LOAD_VAR __mm_key
        #   t_ctr  = LOAD_VAR __mm_ctr
        #   t_c    = LOAD_INDEX __mm_ctr[name]  (call counter)
        #   t_nc   = ADD t_c, 1
        #   STORE_INDEX __mm_ctr[name] ← t_nc
        #   t_hash = CALL hash, (__mm_key, *args)
        #   t_xor  = BXOR t_hash, t_c
        #   t_mod  = MOD t_xor, N
        #   ... build list of variant funcs, index by t_mod, call

        t_key  = dispatch_fn.new_temp()
        t_ctr  = dispatch_fn.new_temp()
        t_c    = dispatch_fn.new_temp()
        t_nc   = dispatch_fn.new_temp()
        t_hash = dispatch_fn.new_temp()
        t_xor  = dispatch_fn.new_temp()
        t_mod  = dispatch_fn.new_temp()
        t_vlist= dispatch_fn.new_temp()
        t_vfn  = dispatch_fn.new_temp()
        t_ret  = dispatch_fn.new_temp()

        def emit(op, dst=None, src=None, label=None, **meta):
            instr = IRInstruction(op=op, dst=dst, src=src or [],
                                  label=label, metadata=meta)
            entry.emit(instr)

        # Load session key + counter
        emit(IROp.LOAD_VAR,   dst=_REG(t_key),  src=[_VAR("__mm_key")])
        emit(IROp.LOAD_VAR,   dst=_REG(t_ctr),  src=[_VAR("__mm_ctr")])
        emit(IROp.LOAD_INDEX, dst=_REG(t_c),
             src=[_REG(t_ctr), _CONST(name)],
             metadata={"default_zero": True})

        # Increment counter
        emit(IROp.ADD,        dst=_REG(t_nc),
             src=[_REG(t_c), _CONST(1)])
        emit(IROp.STORE_INDEX, src=[_REG(t_ctr), _CONST(name), _REG(t_nc)])

        # hash((key, *args))
        hash_args = [_VAR("hash"), _REG(t_key)] + [_VAR(a) for a in args]
        emit(IROp.CALL, dst=_REG(t_hash), src=hash_args,
             metadata={"nargs": len(args) + 1})

        # variant_id = (hash ^ counter) % N
        emit(IROp.BXOR, dst=_REG(t_xor), src=[_REG(t_hash), _REG(t_c)])
        emit(IROp.MOD,  dst=_REG(t_mod), src=[_REG(t_xor), _CONST(n)])

        # Build variant list and index into it
        var_name_ops = [IROperand("func_ref", v.name) for v in variants]
        emit(IROp.BUILD_LIST, dst=_REG(t_vlist),
             src=var_name_ops + [IROperand("count", n)])
        emit(IROp.LOAD_INDEX, dst=_REG(t_vfn),
             src=[_REG(t_vlist), _REG(t_mod)])

        # Call selected variant with original args
        call_args = [_REG(t_vfn)] + [_VAR(a) for a in args]
        emit(IROp.CALL, dst=_REG(t_ret), src=call_args,
             metadata={"nargs": len(args)})

        emit(IROp.RETURN, src=[_REG(t_ret)])

        self._dispatched.add(name)
        return dispatch_fn

    @staticmethod
    def emit_module_preamble() -> str:
        """Python source to inject at top of obfuscated output."""
        return (
            "import random as _mm_rand\n"
            "__mm_key = _mm_rand.getrandbits(64)\n"
            "__mm_ctr = {}\n"
        )
