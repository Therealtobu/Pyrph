import random
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd, cwd=REPO_ROOT):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _obfuscate(src: Path, out: Path, profile: str = "fast"):
    proc = _run([
        sys.executable,
        "cli.py",
        str(src),
        "-o",
        str(out),
        "--profile",
        profile,
        "--no-banner",
        "-q",
    ])
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_randomized_obfuscate_execute_consistency(tmp_path):
    src = tmp_path / "prog.py"
    src.write_text(
        """
def g(n):
    if n <= 1:
        return n
    return g(n - 1) + g(n - 2)

def calc(x):
    a = sum((i * i - i) for i in range(x))
    b = g(x % 8)
    c = {k: (k ^ 3) for k in range(6)}
    return a + b + c[x % 6]

if __name__ == '__main__':
    import sys
    n = int(sys.argv[1])
    print(calc(n))
""".strip()
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "prog_obf.py"
    _obfuscate(src, out, profile="max")

    rnd = random.Random(2026)
    for _ in range(12):
        n = rnd.randrange(0, 32)
        plain = _run([sys.executable, str(src), str(n)])
        obf = _run([sys.executable, str(out), str(n)])
        assert plain.returncode == 0
        assert obf.returncode == 0
        assert plain.stdout == obf.stdout


def test_same_obfuscated_output_is_stable_across_repeated_runs(tmp_path):
    src = tmp_path / "stable.py"
    src.write_text(
        """
from collections import deque

def main():
    d = deque(range(10))
    d.rotate(3)
    print(sum(d), list(d)[:4])

if __name__ == '__main__':
    main()
""".strip()
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "stable_obf.py"
    _obfuscate(src, out, profile="fast")

    outputs = []
    for _ in range(10):
        proc = _run([sys.executable, str(out)])
        assert proc.returncode == 0, proc.stderr
        outputs.append(proc.stdout)

    assert len(set(outputs)) == 1


def test_empty_and_large_inputs_obfuscate_and_execute(tmp_path):
    empty = tmp_path / "empty.py"
    empty.write_text("", encoding="utf-8")
    empty_out = tmp_path / "empty_obf.py"
    _obfuscate(empty, empty_out, profile="fast")
    run_empty = _run([sys.executable, str(empty_out)])
    assert run_empty.returncode == 0

    large = tmp_path / "large.py"
    body = ["def f0(x):\n    return x\n"]
    for i in range(1, 240):
        body.append(f"def f{i}(x):\n    return f{i-1}(x) + {i}\n")
    body.append("if __name__ == '__main__':\n    print(f239(1))\n")
    large.write_text("\n".join(body), encoding="utf-8")
    large_out = tmp_path / "large_obf.py"
    _obfuscate(large, large_out, profile="stealth")

    plain = _run([sys.executable, str(large)])
    obf = _run([sys.executable, str(large_out)])
    assert plain.returncode == 0
    assert obf.returncode == 0
    assert plain.stdout == obf.stdout


def test_max_profile_with_decorators_never_emits_invalid_syntax(tmp_path):
    src = tmp_path / "decorated.py"
    src.write_text(
        """
from functools import wraps

def deco(fn):
    @wraps(fn)
    def wrapper(x):
        return fn(x) + 1
    return wrapper

@deco
def f(n):
    if n <= 1:
        return 1
    return n + f(n - 1)

if __name__ == '__main__':
    import sys
    print(f(int(sys.argv[1])))
""".strip()
        + "\n",
        encoding="utf-8",
    )

    for i in range(8):
        out = tmp_path / f"decorated_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        plain = _run([sys.executable, str(src), "5"])
        obf = _run([sys.executable, str(out), "5"])
        assert plain.returncode == 0
        assert obf.returncode == 0, obf.stderr
        assert plain.stdout == obf.stdout


def test_max_profile_compare_ops_do_not_use_uninitialized_split_tmp(tmp_path):
    src = tmp_path / "cmp_split.py"
    src.write_text(
        """
def run():
    a = 7
    b = 3
    print(a < b, a > b, a <= b, a >= b)

if __name__ == '__main__':
    run()
""".strip()
        + "\n",
        encoding="utf-8",
    )

    expected = _run([sys.executable, str(src)])
    assert expected.returncode == 0

    for i in range(20):
        out = tmp_path / f"cmp_split_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        obf = _run([sys.executable, str(out)])
        assert obf.returncode == 0, obf.stderr
        assert obf.stdout == expected.stdout


def test_max_profile_binary_operand_resolution_matrix_is_stable(tmp_path):
    src = tmp_path / "binary_matrix.py"
    src.write_text(
        """
def run(n):
    i = n or 1
    vals = []
    vals.append(3 + i); vals.append(i + 3)
    vals.append(3 - i); vals.append(i - 3)
    vals.append(3 * i); vals.append(i * 3)
    vals.append(9 / i); vals.append(i / 3)
    vals.append(9 % i); vals.append(i % 3)
    vals.append(3 < i); vals.append(i < 3)
    vals.append(3 > i); vals.append(i > 3)
    vals.append(3 <= i); vals.append(i <= 3)
    vals.append(3 >= i); vals.append(i >= 3)
    vals.append(3 == i); vals.append(i == 3)
    vals.append(3 != i); vals.append(i != 3)
    vals.append(6 & i); vals.append(i & 6)
    vals.append(6 | i); vals.append(i | 6)
    vals.append(6 ^ i); vals.append(i ^ 6)
    vals.append(24 >> i); vals.append(i >> 1)
    vals.append(3 << i); vals.append(i << 1)
    vals.append(i + (i + 1)); vals.append((i + 2) + i)
    vals.append(i - (i + 1)); vals.append((i + 2) - i)
    vals.append(i * (i + 1)); vals.append((i + 2) * i)
    vals.append((i + 8) / (i + 1)); vals.append((i + 8) % (i + 1))
    vals.append((i + 8) >> 1); vals.append((i + 1) << 1)
    print("|".join(str(v) for v in vals))

if __name__ == '__main__':
    run(2)
""".strip()
        + "\n",
        encoding="utf-8",
    )

    expected = _run([sys.executable, str(src)])
    assert expected.returncode == 0, expected.stderr

    for i in range(20):
        out = tmp_path / f"binary_matrix_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        compile(out.read_text(encoding="utf-8"), str(out), "exec")
        obf = _run([sys.executable, str(out)])
        assert obf.returncode == 0, obf.stderr
        assert obf.stdout == expected.stdout


def test_max_profile_vm_register_coherence_across_slots(tmp_path):
    src = tmp_path / "vm_reg_coherence.py"
    src.write_text(
        """
def run(n):
    x = 1
    y = 2
    out = []
    for i in range(1, n + 1):
        x = ((x << 1) ^ (i + 3)) & 0xFFFF
        y = ((y >> 1) ^ (x | i)) & 0xFFFF
        out.append((x ^ y) + (x >> 1) - (y << 1))
    print(sum(out), out[-1], x, y)

if __name__ == '__main__':
    run(30)
""".strip()
        + "\n",
        encoding="utf-8",
    )

    expected = _run([sys.executable, str(src)])
    assert expected.returncode == 0, expected.stderr

    for i in range(30):
        out = tmp_path / f"vm_reg_coherence_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        compile(out.read_text(encoding="utf-8"), str(out), "exec")
        obf = _run([sys.executable, str(out)])
        assert obf.returncode == 0, obf.stderr
        assert obf.stdout == expected.stdout


def test_max_profile_const_compare_and_bitwise_never_resolve_none(tmp_path):
    src = tmp_path / "const_cmp_bits.py"
    src.write_text(
        """
def run():
    a = (3 <= 5, 7 >= 2, 4 == 4, 9 != 1, 2 < 3, 5 > 1)
    b = ((8 ^ 3), (8 | 3), (8 & 3), (16 >> 2), (3 << 2))
    c = ((10 <= 10), (6 >> 1), (6 ^ 6))
    print(a, b, c)

if __name__ == '__main__':
    run()
""".strip()
        + "\n",
        encoding="utf-8",
    )
    expected = _run([sys.executable, str(src)])
    assert expected.returncode == 0, expected.stderr

    for i in range(30):
        out = tmp_path / f"const_cmp_bits_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        compile(out.read_text(encoding="utf-8"), str(out), "exec")
        obf = _run([sys.executable, str(out)])
        assert obf.returncode == 0, obf.stderr
        assert obf.stdout == expected.stdout


def test_max_profile_unary_pow_and_const_shift_are_stable(tmp_path):
    src = tmp_path / "unary_pow_shift.py"
    src.write_text(
        """
def run():
    x = 2 ** 7
    y = ~5
    z = -9
    n = not 0
    a = 24 >> 2
    b = 3 <= 5
    c = (2 ** 3) + (~1) + (-4) + (8 >> 1)
    print(x, y, z, n, a, b, c)

if __name__ == '__main__':
    run()
""".strip()
        + "\n",
        encoding="utf-8",
    )
    expected = _run([sys.executable, str(src)])
    assert expected.returncode == 0, expected.stderr

    for i in range(30):
        out = tmp_path / f"unary_pow_shift_obf_{i}.py"
        _obfuscate(src, out, profile="max")
        compile(out.read_text(encoding="utf-8"), str(out), "exec")
        obf = _run([sys.executable, str(out)])
        assert obf.returncode == 0, obf.stderr
        assert obf.stdout == expected.stdout
