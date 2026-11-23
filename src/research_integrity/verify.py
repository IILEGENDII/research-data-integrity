from pathlib import Path

from .inventory import MAX_ENTRIES, scan
from .manifest import load_manifest
from .models import InputError, Issue, TrustError
from .paths import outside
from .report import Report
from .signing import authenticate
from .storage import new_path


def file_ids(*paths):
    identities = set()
    for path in paths:
        if path is not None:
            info = path.lstat()
            identities.add((info.st_dev, info.st_ino))
    return identities


def compare(payload, current, report):
    expected = {e["path"]: e for e in payload["files"]}
    report.expected_files = len(expected)
    report.bytes_read = current.bytes_read
    report.files_scanned = len(current.files)
    report.errors.extend(current.errors)
    uncertain = {e.path for e in current.errors}
    for path in sorted(expected.keys() | current.files.keys()):
        baseline = expected.get(path)
        observed = current.files.get(path)
        if observed is None:
            # An inaccessible directory hides its children. Absence cannot be inferred there.
            parts = path.split("/")
            if "." in uncertain or any(
                "/".join(parts[:i]) in uncertain for i in range(1, len(parts) + 1)
            ):
                continue
            status = "missing"
        elif baseline is None:
            status = "added"
        elif observed.sha256 == baseline["sha256"] and observed.size == baseline["size"]:
            status = "unchanged"
        else:
            status = "modified"
        row = {"path": path, "status": status}
        if status == "modified":
            row.update(
                expected_sha256=baseline["sha256"],
                expected_size=baseline["size"],
                observed_sha256=observed.sha256,
                observed_size=observed.size,
            )
        report.findings.append(row)


def verify(
    root: Path,
    manifest: Path,
    public_key: Path | None,
    allow_unsigned: bool,
    output: Path | None = None,
    *,
    max_entries=MAX_ENTRIES,
) -> Report:
    report = Report()
    try:
        root = root.absolute()
        manifest = outside(manifest, root)
        doc = load_manifest(manifest, max_entries=max_entries)
        if public_key is not None:
            public_key = outside(public_key, root)
        report.trust = authenticate(doc, public_key, allow_unsigned, max_entries=max_entries)
        report.expected_files = len(doc["payload"]["files"])
        if output is not None:
            new_path(outside(output, root))
        current = scan(root, protected=file_ids(manifest, public_key), max_entries=max_entries)
        compare(doc["payload"], current, report)
    except TrustError as exc:
        report.trust = "failed"
        report.errors.append(Issue("signature_invalid", None, str(exc)))
    except InputError as exc:
        report.errors.append(Issue("input_error", None, str(exc)))
    except OSError:
        report.errors.append(
            Issue("io_error", None, "Cannot access the selected input or output.")
        )
    return report
