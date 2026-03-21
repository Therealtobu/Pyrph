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
