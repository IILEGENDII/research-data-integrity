"""One independently signed, synthetic dataset per controlled verification."""

import json

import pytest

from research_integrity import hashing, signing

SCENARIOS = [
    ("clean", 0, "unchanged"),
    ("replace", 1, "modified"),
    ("same-size", 1, "modified"),
    ("add", 1, "added"),
    ("delete", 1, "missing"),
    ("tamper", 3, "signature_invalid"),
    ("wrong-key", 3, "signature_invalid"),
    ("traversal", 2, "input_error"),
    ("symlink", 2, "unsupported"),
    ("mid-read", 2, "unstable"),
]


@pytest.mark.parametrize(
    ("scenario", "expected", "status"), SCENARIOS, ids=[s[0] for s in SCENARIOS]
)
def test_scenario(scenario, expected, status, signed_dataset, run_verify, monkeypatch, capsys):
    root, manifest, public = signed_dataset
    frame = root / "frame.bin"
    if scenario == "replace":
        frame.write_bytes(b"replacement")
    elif scenario == "same-size":
        frame.write_bytes(b"4321")
    elif scenario == "add":
        (root / "new.bin").write_bytes(b"added")
    elif scenario == "delete":
        (root / "checkpoint").unlink()
    elif scenario in {"tamper", "traversal"}:
        doc = json.loads(manifest.read_text())
        entry = doc["payload"]["files"][0]
        if scenario == "tamper":
            entry["sha256"] = "0" * 64
        else:
            entry["path"] = "../outside"
        manifest.write_text(json.dumps(doc))
    elif scenario == "wrong-key":
        public = manifest.parent / "other-public.pem"
        signing.generate_keys(
            manifest.parent / "other-private.pem", public, b"disposable fixture"
        )
    elif scenario == "symlink":
        try:
            (root / "link").symlink_to(public)
        except OSError:
            pytest.skip("file symlinks unavailable")
    elif scenario == "mid-read":
        original = hashing.hashlib.sha256

        def digest():
            instance = original()

            class Updating:
                def update(self, block):
                    instance.update(block)
                    if block == b"1234":
                        with frame.open("ab") as writer:
                            writer.write(b"5")

                def hexdigest(self):
                    return instance.hexdigest()

            return Updating()

        monkeypatch.setattr(
            hashing.hashlib, "sha256", lambda *args: original(*args) if args else digest()
        )
    code, report = run_verify(root, manifest, public)
    assert code == expected
    assert status in {r["status"] for r in report["findings"] + report["errors"]}
    if code == 3 or scenario == "traversal":
        assert report["summary"]["bytes_read"] == 0 and not report["findings"]
    with capsys.disabled():
        print(f"{scenario:10} exit={code} result={report['result']} observation={status}")
