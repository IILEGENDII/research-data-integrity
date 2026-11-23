import argparse
import sys
from pathlib import Path

from . import __version__, signing
from .demo import create_demo
from .inventory import MAX_ENTRIES, scan
from .manifest import load_manifest, make_payload, save_manifest
from .models import InputError, Issue, TrustError
from .paths import dataset_root, outside
from .report import display, render
from .storage import new_path, write_new
from .verify import file_ids, verify

WARNING = "UNAUTHENTICATED: an unsigned manifest can be edited along with the data."


def entry_limit(value):
    number = int(value)
    if not 1 <= number <= 250_000:
        raise argparse.ArgumentTypeError("choose between 1 and 250000 entries")
    return number


def parser():
    cli = argparse.ArgumentParser(
        prog="research-integrity",
        description="Record and verify signed SHA-256 inventories of local research files.",
        epilog="Example: research-integrity verify data --manifest control/base.json --public-key keys/public.pem",
    )
    cli.add_argument("--version", action="version", version=__version__)
    commands = cli.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen", help="create an encrypted Ed25519 key pair")
    keys.add_argument("--private-key", type=Path, required=True)
    keys.add_argument("--public-key", type=Path, required=True)
    base = commands.add_parser("baseline", help="record a new dataset inventory")
    base.add_argument("root", type=Path)
    base.add_argument("--output", type=Path, required=True)
    choice = base.add_mutually_exclusive_group(required=True)
    choice.add_argument("--sign-key", type=Path)
    choice.add_argument("--unsigned", action="store_true")
    check = commands.add_parser(
        "verify", help="authenticate the inventory and compare current files"
    )
    check.add_argument("root", type=Path)
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument("--output", type=Path)
    inspect = commands.add_parser("inspect", help="authenticate and summarize a manifest")
    inspect.add_argument("manifest", type=Path)
    for command in (check, inspect):
        command.add_argument("--public-key", type=Path)
        command.add_argument("--allow-unsigned", action="store_true")
    for command in (base, check, inspect):
        command.add_argument(
            "--max-entries",
            type=entry_limit,
            default=MAX_ENTRIES,
            help="file and directory budget (default 100000, maximum 250000)",
        )
    demo = commands.add_parser("demo", help="create a new synthetic workspace")
    demo.add_argument("--output", type=Path, required=True)
    return cli


def baseline(args):
    root = dataset_root(args.root)
    output = new_path(outside(args.output, root))
    key = None
    protected = set()
    if args.sign_key is not None:
        key_path = outside(args.sign_key, root)
        key = signing.load_private(key_path, signing.passphrase())
        protected = file_ids(key_path)
    else:
        print(WARNING, file=sys.stderr)
    current = scan(root, protected=protected, max_entries=args.max_entries)
    if current.errors:
        for e in current.errors:
            print(f"{e.status}: {display(e.path or '.')}  {e.message}", file=sys.stderr)
        raise InputError("Incomplete scan. No baseline was written.")
    payload = make_payload(current)
    doc = (
        signing.sign(payload, key, max_entries=args.max_entries)
        if key
        else {"payload": payload, "signature": None}
    )
    save_manifest(output, doc, max_entries=args.max_entries)
    print(
        f"Manifest: {display(str(args.output))} | SHA-256 | {'SIGNED' if key else 'UNAUTHENTICATED'}"
    )
    print(f"Files: {len(current.files)} | Bytes: {current.bytes_read}")


def verification(args):
    report = verify(
        args.root,
        args.manifest,
        args.public_key,
        args.allow_unsigned,
        args.output,
        max_entries=args.max_entries,
    )
    if report.trust == "unauthenticated":
        print(WARNING, file=sys.stderr)
    if args.output is not None:
        try:
            output = outside(args.output, args.root.absolute())
            write_new(output, render(report, args.format).encode("utf-8"))
            return report.exit_code
        except (OSError, InputError):
            print(
                "Cannot create report at the selected output. Reporting on stdout.",
                file=sys.stderr,
            )
            report.errors.append(
                Issue("output_error", None, "Report destination unavailable or unsafe.")
            )
    sys.stdout.write(render(report, args.format))
    sys.stdout.flush()
    return report.exit_code


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "verify":
            return verification(args)
        if args.command == "demo":
            create_demo(args.output)
            print("Created synthetic dataset and WALKTHROUGH.txt.")
        elif args.command == "baseline":
            baseline(args)
        elif args.command == "keygen":
            private, public = new_path(args.private_key), new_path(args.public_key)
            fp = signing.generate_keys(private, public, signing.passphrase(confirm=True))
            print(f"Public key fingerprint: {fp}")
        elif args.command == "inspect":
            doc = load_manifest(args.manifest, max_entries=args.max_entries)
            trust = signing.authenticate(
                doc, args.public_key, args.allow_unsigned, max_entries=args.max_entries
            )
            if trust == "unauthenticated":
                print(WARNING, file=sys.stderr)
            p = doc["payload"]
            fp = doc["signature"]["public_key_fingerprint"] if doc["signature"] else "none"
            print(
                f"Schema: {p['schema_version']} | Hash: {p['algorithm']} | Created: {p['created_at']}"
            )
            print(f"Manifest trust: {trust.upper()} | Fingerprint: {fp}")
            print(f"Files: {len(p['files'])} | Bytes: {sum(e['size'] for e in p['files'])}")
    except TrustError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except InputError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("Filesystem or output encoding error.", file=sys.stderr)
        return 2
    return 0
