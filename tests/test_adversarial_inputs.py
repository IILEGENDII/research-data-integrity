import base64
import json

import pytest

from research_integrity import signing
from research_integrity.cli import main
from research_integrity.manifest import canonical


def test_signed_unsafe_path(signed_dataset, run_verify):
    root, manifest, public = signed_dataset
    doc = json.loads(manifest.read_text())
    doc["payload"]["files"][0]["path"] = "../external"
    key = signing.load_private(root.parent / "private.pem", b"synthetic fixture")
    doc["signature"]["value"] = base64.b64encode(key.sign(canonical(doc["payload"]))).decode()
    manifest.write_text(json.dumps(doc))
    code, result = run_verify(root, manifest, public)
    assert (
        code == 2 and result["summary"]["bytes_read"] == 0 and result["result"] == "incomplete"
    )


def test_trust_error_precedes_output_error(signed_dataset, run_verify):
    root, manifest, _ = signed_dataset
    code, report = run_verify(root, manifest, None, "--output", str(root / "invalid"))
    assert code == 3 and report["manifest_trust"] == "failed"
    assert report["summary"]["bytes_read"] == 0 and not (root / "invalid").exists()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(unknown=None),
        lambda doc: doc["signature"].update(algorithm="unknown"),
        lambda doc: doc["signature"].update(public_key_fingerprint="bad"),
        lambda doc: doc["payload"].pop("algorithm"),
    ],
)
def test_schema_rejection(signed_dataset, run_verify, mutate):
    root, path, key = signed_dataset
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc))
    code, report = run_verify(root, path, key)
    assert code == 2 and report["summary"]["bytes_read"] == 0


def test_caller_limits(signed_dataset, run_verify):
    root, path, key = signed_dataset
    code, report = run_verify(root, path, key, "--max-entries", "1")
    assert code == 2 and report["summary"]["files_scanned"] == 0
    with pytest.raises(SystemExit) as exc:
        main(["inspect", str(path), "--max-entries", "250001"])
    assert exc.value.code == 2


def test_unsigned_flags_are_explicit(tmp_path):
    for flags in [[], ["--unsigned", "--sign-key", "key"]]:
        with pytest.raises(SystemExit) as exc:
            main(["baseline", str(tmp_path), "--output", "base", *flags])
        assert exc.value.code == 2
