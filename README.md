# Research Data Integrity Monitor

A researcher can sign an inventory of a local dataset before moving or archiving it, then verify the files against that inventory later. The monitor streams every regular file through SHA-256. It reports changed bytes, new files, missing files, and anything it could not safely read. Verification leaves dataset contents alone.

A signed manifest binds the inventory to an Ed25519 key. Keep a trusted copy of the public key somewhere the dataset's writers cannot replace it. A match establishes equality to the signed baseline. Baseline quality, data recovery, and the cause of a change require separate evidence.

## Install from this checkout

Python 3.11 or later is required. GitHub Actions runs the tests on Linux, Windows, and macOS. [Hosted checks](https://github.com/IILEGENDII/research-data-integrity/actions/workflows/ci.yml)

In PowerShell, run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

On Linux or macOS, run:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Use `research-integrity --help` or `python -m research_integrity --help` to see the commands.

## Try a signed comparison

Run these commands in an interactive terminal. Use a new directory name for each demo. Key generation asks for a passphrase twice. Signing asks for it once. Verification needs only the public key.

```sh
research-integrity demo --output demo-workspace
cd demo-workspace
research-integrity keygen --private-key keys/private.pem --public-key keys/public.pem
research-integrity baseline data --output control/base.json --sign-key keys/private.pem
research-integrity inspect control/base.json --public-key keys/public.pem
research-integrity verify data --manifest control/base.json --public-key keys/public.pem
```

The initial comparison printed:

```text
Manifest trust: VERIFIED
Result: clean
Files scanned: 3 | Bytes read: 75
Unchanged: 3 | Modified: 0 | Added: 0 | Missing: 0 | Errors: 0
```

Append one row to the synthetic material table and run the same verification:

```sh
python -c "from pathlib import Path; p = Path('data/inputs/material.csv'); p.write_bytes(p.read_bytes() + b'C,1.75\n')"
research-integrity verify data --manifest control/base.json --public-key keys/public.pem
```

The second comparison returned exit code 1 and printed:

```text
Manifest trust: VERIFIED
Result: differences
Files scanned: 3 | Bytes read: 82
Unchanged: 2 | Modified: 1 | Added: 0 | Missing: 0 | Errors: 0
MODIFIED  inputs/material.csv
  expected: 29 bytes  9ef4b232f79788c5a2c65775b35da1eb06695e2cd45df87033fdcc9200e05a6f
  observed: 36 bytes  000e5ed43664bd25a19e20f0dfc614e825cba0c90a5d2572a80a7a5883b3a26e
```

To save structured findings, append `--format json --output reports/check-1.json` to the verification command. Output files must be new and outside the dataset. Keep passphrases, private keys, real research data, and sensitive inventories out of Git.

| Exit | Meaning |
| ---: | --- |
| 0 | Successful operation or complete comparison with every file unchanged |
| 1 | Complete comparison found differences |
| 2 | Invalid input, unsafe path, or incomplete operation |
| 3 | Manifest trust or signing-key failure |

A trust failure takes priority over an operational failure, which takes priority over differences. For an explicitly unauthenticated checksum workflow, create a baseline with `--unsigned` and verify with `--allow-unsigned` and no expected key. Anyone able to rewrite both datasets and unsigned manifests can make them agree.

## Documentation

- [Threat model](docs/threat-model.md) and [key management](docs/key-management.md)
- [Manifest format and public test vector](docs/manifest-format.md) and [design decisions](docs/design-decisions.md)
- [Filesystem and security limitations](docs/limitations.md)
- [Controlled tests](docs/controlled-tests.md), [performance measurements](docs/evaluation.md), and [test source](tests/)
- [Engineering verification and release checklist](docs/verification.md)
- [Contribution guide](CONTRIBUTING.md) and [private security reporting](SECURITY.md)
