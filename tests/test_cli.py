import subprocess
import sys

from research_integrity import __version__


def test_installed_module():
    result = subprocess.run(
        [sys.executable, "-I", "-m", "research_integrity", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == __version__ == "0.1.0"
