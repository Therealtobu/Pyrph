import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm.interleaver import Interleaver
from vm.opcodes import VM1Op, VM2Op


class _Op:
    def __init__(self, kind, value):
        self.kind = kind
        self.value = value


def test_emit_operand_split_maps_kinds():
    assert Interleaver._emit_operand(_Op("const", 1), "A") == VM1Op.RLOAD_CONST
    assert Interleaver._emit_operand(_Op("const_ref", 4), "A") == VM1Op.RLOAD_CONST
    assert Interleaver._emit_operand(_Op("str_ref", 9), "A") == VM1Op.RLOAD_CONST
    assert Interleaver._emit_operand(_Op("var", "x"), "A") == VM1Op.RLOAD_VAR
    assert Interleaver._emit_operand(_Op("reg", 2), "A") == VM1Op.RLOAD_VAR
    assert Interleaver._emit_operand(_Op("const", 1), "B") == VM2Op.WLOAD_K
    assert Interleaver._emit_operand(_Op("var", "x"), "B") == VM2Op.WLOAD_V


def test_emit_operand_split_rejects_invalid_kind():
    with pytest.raises(RuntimeError, match="Invalid operand kind"):
        Interleaver._emit_operand(_Op("label", "L1"), "A")
