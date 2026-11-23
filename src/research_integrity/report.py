import json
from dataclasses import asdict, dataclass, field

from .models import Issue

STATUSES = (
    "unchanged",
    "modified",
    "added",
    "missing",
    "unsupported",
    "unreadable",
    "unstable",
    "signature_invalid",
)


@dataclass
class Report:
    trust: str = "unknown"
    expected_files: int | None = None
    files_scanned: int = 0
    bytes_read: int = 0
    findings: list[dict] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)

    @property
    def exit_code(self):
        if self.trust == "failed":
            return 3
        if self.errors:
            return 2
        return int(any(item["status"] != "unchanged" for item in self.findings))

    def document(self):
        counts = dict.fromkeys(STATUSES, 0)
        for item in self.findings:
            counts[item["status"]] += 1
        for error in self.errors:
            if error.status in counts:
                counts[error.status] += 1
        return {
            "schema_version": 1,
            "result": ("clean", "differences", "incomplete", "trust_failure")[self.exit_code],
            "manifest_trust": self.trust,
            "summary": {
                **counts,
                "expected_files": self.expected_files,
                "files_scanned": self.files_scanned,
                "bytes_read": self.bytes_read,
                "errors": len(self.errors),
            },
            "findings": self.findings,
            "errors": [asdict(e) for e in self.errors],
        }


def display(value: str) -> str:
    return "".join(c if c.isprintable() else ascii(c)[1:-1] for c in value)


def render(report: Report, fmt: str) -> str:
    doc = report.document()
    if fmt == "json":
        return json.dumps(doc, ensure_ascii=True, indent=2) + "\n"
    s = doc["summary"]
    lines = [
        f"Manifest trust: {report.trust.upper()}",
        f"Result: {doc['result']}",
        f"Files scanned: {report.files_scanned} | Bytes read: {report.bytes_read}",
        " | ".join(
            f"{k.capitalize()}: {s[k]}"
            for k in ("unchanged", "modified", "added", "missing", "errors")
        ),
    ]
    for item in report.findings:
        status = item["status"]
        if status == "unchanged":
            continue
        lines.append(f"{status.upper()}  {display(item['path'])}")
        if status == "modified":
            for side in ("expected", "observed"):
                lines.append(
                    f"  {side}: {item[side + '_size']} bytes  {item[side + '_sha256']}"
                )
    for error in report.errors:
        lines.append(f"{error.status.upper()}  {display(error.path or '.')}  {error.message}")
    return "\n".join(lines) + "\n"
