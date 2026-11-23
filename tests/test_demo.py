import pytest

from research_integrity.cli import main
from research_integrity.demo import create_demo
from research_integrity.models import InputError


def test_demo(tmp_path):
    output = tmp_path / "workspace"
    assert main(["demo", "--output", str(output)]) == 0
    assert len(list((output / "data").rglob("*.*"))) == 3
    assert "research-integrity verify" in (output / "WALKTHROUGH.txt").read_text()
    with pytest.raises(InputError):
        create_demo(output)
    empty = tmp_path / "existing"
    empty.mkdir()
    assert main(["demo", "--output", str(empty)]) == 2
    assert not list(empty.iterdir())
