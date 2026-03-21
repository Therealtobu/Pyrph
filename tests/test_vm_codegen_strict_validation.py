import pytest

from vm.codegen import VMCodeGen
from vm.interleaver import VM3Bytecode


def _minimal_bc() -> VM3Bytecode:
    return VM3Bytecode(
        instructions=[],
        const_table={},
        string_table={},
        seed_key1=1,
        seed_key2=2,
        sched_seed=3,
        sched_period=32,
        label_map={},
    )


def test_generate_rejects_missing_bytecode():
    gen = VMCodeGen()
    with pytest.raises(RuntimeError, match="requires VM3Bytecode"):
        gen.generate(None)


def test_generate_rejects_invalid_tables():
    gen = VMCodeGen()
    bc = _minimal_bc()
    bc.string_table = []
    with pytest.raises(RuntimeError, match="string_table"):
        gen.generate(bc)


def test_runtime_order_validation_rejects_sr_init_before_class():
    bad = "__SR = _SR(__FRAGS, __FIDX)\nclass _SR:\n    pass\n"
    with pytest.raises(RuntimeError, match="Invalid VM emission order"):
        VMCodeGen._validate_runtime_order(bad)


def test_runtime_order_validation_rejects_missing_sr_class():
    bad = "__SR = _SR(__FRAGS, __FIDX)\n"
    with pytest.raises(RuntimeError, match="missing _SR definition"):
        VMCodeGen._validate_runtime_order(bad)
