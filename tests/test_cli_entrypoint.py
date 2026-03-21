import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_cli_dry_run_works_without_installed_package(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "cli.py",
            str(sample),
            "--profile",
            "fast",
            "--dry-run",
            "--no-banner",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "Pipeline" in proc.stdout


def test_cli_fast_profile_produces_runnable_output(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        """
def main():
    print('RESULT', 6 * 7)

if __name__ == '__main__':
    main()
""".strip()
        + "\n",
        encoding="utf-8",
    )

    out_file = tmp_path / "sample_obf.py"
    obf = subprocess.run(
        [
            sys.executable,
            "cli.py",
            str(sample),
            "-o",
            str(out_file),
            "--profile",
            "fast",
            "--no-banner",
            "-q",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert obf.returncode == 0, obf.stderr or obf.stdout
    assert out_file.exists()

    run = subprocess.run(
        [sys.executable, str(out_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr or run.stdout
    assert "RESULT 42" in run.stdout


def test_cli_handles_empty_input_and_multi_run_stability(tmp_path):
    sample = tmp_path / "empty.py"
    sample.write_text("", encoding="utf-8")
    out_file = tmp_path / "empty_obf.py"

    obf = subprocess.run(
        [
            sys.executable,
            "cli.py",
            str(sample),
            "-o",
            str(out_file),
            "--profile",
            "vm_max",
            "--no-banner",
            "-q",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert obf.returncode == 0, obf.stderr or obf.stdout

    for _ in range(6):
        run = subprocess.run(
            [sys.executable, str(out_file)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert run.returncode == 0, run.stderr or run.stdout
        assert run.stdout == ""


def test_cli_large_nonstandard_program_correctness(tmp_path):
    sample = tmp_path / "complex.py"
    numbers = ",".join(str(i) for i in range(1500))
    sample.write_text(
        f"""
def deco(fn):
    return lambda *a, **k: fn(*a, **k)

@deco
def crunch(xs):
    total = 0
    for i, x in enumerate(xs):
        total += (x * i) if (x % 7) else -(x // 2)
    return total

def deep(n):
    if n <= 1:
        return 1
    return n * deep(n - 1)

def main():
    data = [{numbers}]
    chk = crunch(data)
    val = deep(9) % 997
    text = 'ok' if (p := chk ^ val) else 'zero'
    print(text, p, len(data))

if __name__ == "__main__":
    main()
""".lstrip(),
        encoding="utf-8",
    )

    out_file = tmp_path / "complex_obf.py"
    baseline = subprocess.run(
        [sys.executable, str(sample)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert baseline.returncode == 0, baseline.stderr or baseline.stdout

    obf = subprocess.run(
        [
            sys.executable,
            "cli.py",
            str(sample),
            "-o",
            str(out_file),
            "--profile",
            "balanced",
            "--no-banner",
            "-q",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert obf.returncode == 0, obf.stderr or obf.stdout

    for _ in range(4):
        run = subprocess.run(
            [sys.executable, str(out_file)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert run.returncode == 0, run.stderr or run.stdout
        assert run.stdout == baseline.stdout
