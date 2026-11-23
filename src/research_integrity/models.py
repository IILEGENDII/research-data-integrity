from dataclasses import dataclass, field


class InputError(ValueError):
    """Malformed input or an operation that cannot safely complete."""


class TrustError(ValueError):
    """The requested signature or key could not be authenticated."""


@dataclass(frozen=True)
class Entry:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Issue:
    status: str
    path: str | None
    message: str


@dataclass
class Inventory:
    files: dict[str, Entry] = field(default_factory=dict)
    errors: list[Issue] = field(default_factory=list)
    bytes_read: int = 0
