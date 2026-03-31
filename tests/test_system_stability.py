import random
import subprocess
import sys
from pathlib import Path

from pyrph.phases.unified import build_pipeline
from vm.const_pool import POOL_RUNTIME
from vm4.execution_fabric import ExecutionFabricEmitter


def _run_py(path: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(path), *args],
        capture_output=True,
        text=True,
    )


def test_obfuscate_execute_randomized_inputs_and_multirun_integrity(tmp_path):
    source = (
        "import sys\n"
        "def calc(nums):\n"
        "    acc = 17\n"
        "    for i, n in enumerate(nums):\n"
        "        if i % 3 == 0:\n"
        "            acc = (acc * 7 + n * n - i) % 100003\n"
        "        elif i % 3 == 1:\n"
        "            acc = (acc ^ (n + i * 13))\n"
        "        else:\n"
        "            acc = acc + (n * 5) - (i // 2)\n"
        "    return acc\n"
        "nums = [int(x) for x in sys.argv[1:]]\n"
        "print(calc(nums))\n"
    )

    original = tmp_path / "orig.py"
    obf_file = tmp_path / "obf.py"
    original.write_text(source, encoding="utf-8")

    pipeline = build_pipeline(profile="balanced", native=False, chaos=False)
    obfuscated = pipeline.run(source)[-1].code
    obf_file.write_text(obfuscated, encoding="utf-8")

    rng = random.Random(1337)
    for _ in range(25):
        values = [str(rng.randint(-2000, 2000)) for _ in range(rng.randint(0, 25))]

        ref = _run_py(original, values)
        got = _run_py(obf_file, values)
        assert ref.returncode == 0, ref.stderr
        assert got.returncode == 0, got.stderr
        assert got.stdout == ref.stdout

        # Multi-run integrity: same obfuscated output must stay stable across runs.
        repeats = [_run_py(obf_file, values).stdout for _ in range(6)]
        assert all(x == ref.stdout for x in repeats)


def test_large_generated_input_obfuscates_and_runs(tmp_path):
    funcs = []
    for i in range(150):
        funcs.append(f"def f{i}(x):\n    return (x * {i + 3}) ^ {i * 17}\n")

    body = "\n".join(funcs)
    body += "\ndef run():\n    v = 0\n"
    for i in range(150):
        body += f"    v = f{i}(v + {i})\n"
    body += "    return v\nprint(run())\n"

    original = tmp_path / "large.py"
    obf_file = tmp_path / "large_obf.py"
    original.write_text(body, encoding="utf-8")

    pipeline = build_pipeline(profile="fast", native=False, chaos=False)
    obf = pipeline.run(body)[-1].code
    obf_file.write_text(obf, encoding="utf-8")

    ref = _run_py(original, [])
    got = _run_py(obf_file, [])
    assert ref.returncode == 0, ref.stderr
    assert got.returncode == 0, got.stderr
    assert got.stdout == ref.stdout


def test_execution_fabric_handles_empty_or_invalid_scheduler_state():
    ns = {"__builtins__": __builtins__}
    exec(ExecutionFabricEmitter.emit_runtime(), ns)

    sm_state, dna, hist = ns["_ef_run"]([], [], {}, lambda: 0, 0x1234)
    assert sm_state == {}
    assert dna == 0x1234
    assert hist == []

    assert ns["_ef_pick"](0, 1, 2, 3, 4) == 0
    assert ns["_ef_converged"](set(), [], []) is True


def test_pool_runtime_preserves_bool_values_without_type_corruption():
    ns = {"__builtins__": __builtins__}
    exec(POOL_RUNTIME, ns)

    ns["_CP_STATE"] = 0xBEEF
    ns["_CP_SLOTS"] = {0: [True, 0], 1: [False, 0], 2: [7 ^ 3, 3]}

    assert ns["_cp_get"](0) is True
    assert ns["_cp_get"](1) is False
    assert ns["_cp_get"](2) == 7

    # Repeat reads should remain correct and bool-typed.
    assert ns["_cp_get"](0) is True
    assert ns["_cp_get"](1) is False
