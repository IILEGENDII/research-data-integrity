import shutil
import subprocess
from pathlib import Path

import pytest


def test_ignore_local_inputs(tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("requires Git to evaluate ignore rules")
    source = Path(__file__).resolve().parents[1] / ".gitignore"
    shutil.copyfile(source, tmp_path / ".gitignore")
    subprocess.run([git, "init", "-q"], cwd=tmp_path, check=True)
    sensitive = [
        "keys/signing.pem",
        "signing.key",
        "backup.p12",
        ".env",
        "data/input.csv",
        "demo-workspace/results.dat",
        "reports/check.json",
        "control/base.json",
        "manifest-1.json",
        ".local/min-env",
        "dist/example.whl",
    ]
    check = subprocess.run(
        [git, "check-ignore", "--no-index", "--", *sensitive, "tests/vectors/ed25519-v1.json"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert check.stdout.splitlines() == sensitive
