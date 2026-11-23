import json

import pytest

from research_integrity import signing
from research_integrity.cli import main


@pytest.fixture
def signed_dataset(tmp_path, monkeypatch, capsys):
    root = tmp_path / "data"
    root.mkdir()
    (root / "frame.bin").write_bytes(b"1234")
    (root / "checkpoint").write_bytes(b"012")
    private, public, manifest = (
        tmp_path / name for name in ("private.pem", "public.pem", "base.json")
    )
    monkeypatch.setattr(signing, "passphrase", lambda **kwargs: b"synthetic fixture")
    assert main(["keygen", "--private-key", str(private), "--public-key", str(public)]) == 0
    assert (
        main(["baseline", str(root), "--output", str(manifest), "--sign-key", str(private)])
        == 0
    )
    capsys.readouterr()
    return root, manifest, public


@pytest.fixture
def run_verify(capsys):
    def run(root, manifest, public=None, *extra):
        args = ["verify", str(root), "--manifest", str(manifest), "--format", "json"]
        if public is not None:
            args.extend(["--public-key", str(public)])
        code = main([*args, *extra])
        stream = capsys.readouterr()
        return code, json.loads(stream.out)

    return run
