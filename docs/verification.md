# Engineering verification

This record covers the 0.1.0 local release candidate. Every dataset used in testing was disposable and synthetic.

## Implementation and phase gates

| Phase | Implementation checked | Observed Windows pytest result before advancing |
| --- | --- | --- |
| 1 | Installable package, module and CLI | 1 passed |
| 2 | Streaming SHA-256, filesystem inventory, unstable-input checks | 5 passed, 2 skipped |
| 3 | Versioned JSON, canonical bytes, path validation and exclusive output | 50 passed, 2 skipped |
| 4 | Ed25519 keys, signing, trust checks and downgrade handling | 62 passed, 2 skipped |
| 5 | Baseline, verify, inspect, reports and exit codes | 71 passed, 2 skipped |
| 6 | Demo, ten controlled scenarios, synthetic benchmark | 81 passed, 3 skipped |
| 7 | Filesystem, error precedence, malformed-input and race tests | 96 passed, 5 skipped |
| 8 | Documentation, public vector, Git hygiene, CI configuration, isolated build and clean installs | 98 passed, 5 skipped |
| 9 | Engineering report, artifact checks and final suite | See the final checks below |

Linux also ran all 84 phase 6 tests and all 101 phase 7 tests. During development, the Windows file-identity checks needed a platform-specific correction because the path and descriptor APIs can differ on change time. Checks still compare file identity, type, size and modification time on Windows.

The implementation lives in `src/research_integrity/`. The CLI exposes `keygen`, `baseline`, `verify`, `inspect`, and `demo`. Inventory and hashing read data, paths and storage enforce local I/O constraints, manifest and signing handle trust, and verify and report handle comparisons. Tests cover these modules and both CLI entry points. The repository also includes versioned packaging metadata, a read-only GitHub Actions workflow, synthetic examples, a public signature vector, and operator documentation.

## Reproduce the local checks

From a fresh checkout in an activated virtual environment, run:

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest -q -rs --cov=research_integrity --cov-report=term-missing
python -m pytest -q -s tests/test_scenarios.py
python -m pytest -q -s tests/test_terminal.py
python -m research_integrity --help
research-integrity --version
python examples/benchmark.py 4 16 64
python -m build
```

The signed walkthrough includes actual clean and modified output. The scenario table records individual command outcomes, including exits 1, 2 and 3 when expected. Pytest's own success exit is 0. [Walkthrough](../README.md#try-a-signed-comparison) · [Scenarios](controlled-tests.md) · [Benchmark](evaluation.md)

## Final checks

| Environment | Full pytest result | Statement coverage |
| --- | --- | --- |
| Windows AMD64, CPython 3.11.18 | 98 passed, 5 skipped | Not measured on 3.11 |
| Windows AMD64, CPython 3.14.7 | 98 passed, 5 skipped | 91%, 699 statements |
| Local Ubuntu 26.04 under WSL, CPython 3.14.4 | 103 passed, zero skips | 91%, 699 statements |

All three pytest commands exited 0. The five Windows skips cover two cases requiring file-symlink creation privileges, a case-collision fixture requiring a case-sensitive filesystem, a POSIX FIFO, and a POSIX pseudo-terminal. The Windows directory-junction and hard-link tests ran with the user's normal permissions. Ubuntu exercised all ten controlled scenarios and drove the real passphrase prompts through a pseudo-terminal. Cases using test doubles are identified in the tests and scenario notes.

The following are the command lines used for the final local checks, with working directories relative to the repository. The two `.local` scripts are local build-verification helpers. The public pytest suite, example scripts, walkthrough, and commands above provide the portable reproduction path.

| Command | Observed outcome | Exit |
| --- | --- | ---: |
| `.venv/Scripts/python.exe -m ruff check .` | No lint findings | 0 |
| `.venv/Scripts/python.exe -m ruff format --check .` | No formatting changes required | 0 |
| `.local/min-env/Scripts/python.exe -m pytest -q -rs` | Windows minimum-version result above | 0 |
| `.venv/Scripts/python.exe -m pytest -q -rs --cov=research_integrity --cov-report=term-missing` | Windows 3.14 result above | 0 |
| `wsl.exe -d Ubuntu-26.04 -- python3 .local/linux_check.py` | Copied source to a fresh Linux filesystem, installed development dependencies from local wheels, ran Ruff, pytest, module version and signed terminal test | 0 |
| `.venv/Scripts/research-integrity.exe --help` and `.venv/Scripts/python.exe -I -m research_integrity --version` | Five subcommands and version 0.1.0 | 0 each |
| `.venv/Scripts/python.exe examples/benchmark.py 4 16 64` | Three completed scans; byte totals and timings in the evaluation | 0 |
| `.venv/Scripts/python.exe -m build` | Source archive and wheel, using isolated environments and the locally cached build dependencies | 0 |
| `.venv/Scripts/python.exe .local/check_dist.py` | Both archive inspections, dependency checks, clean installs and CLI comparisons passed | 0 |
| `git diff --cached --check` | No whitespace errors in staged changes | 0 |

The wheel contains 13 runtime Python modules and six distribution metadata files, including the license. The source archive contains the 48 reviewed source, test, documentation and configuration files plus eight generated packaging files. Each artifact was installed alone in its own empty Windows environment using `pip --python <fresh-python> install <artifact>`. Both passed `pip check`, both CLI help paths, version, an explicitly unsigned 75-byte demo, and signed inspection and verification of the public vector. Neither archive contained a private-key PEM block, an obvious credential matching the checked patterns, a user-specific filesystem path, or a local dataset directory. An explicit Git ignore-rule test covers private keys, local datasets and reports.

Two local tooling failures were corrected during packaging. A Windows test initially sent CRLF-delimited names to Git's stdin. Passing the path arguments directly verified the intended names. The restricted Windows temporary path also caused setuptools wheel staging to fail. The build and both installation checks succeeded offline in the ordinary Windows temporary directory. The CI workflow's synthetic smoke commands ran locally. Hosted Actions, macOS, and Python 3.15 remain unverified. Continuous monitoring, recovery, remote storage, automatic key revocation, and a point-in-time filesystem snapshot are outside v0.1.0.

## Before a verified GitHub release

1. Review the staged paths and `git diff --cached`. Pick the owner and visibility of the **new** repository. Configure the intended Git commit identity. Run `git commit -m "Implement signed local dataset verification"`.
2. Create an empty GitHub repository named `research-data-integrity` under the chosen account. Leave automatic initialization off. Substitute the real owner in `git remote add origin https://github.com/OWNER/research-data-integrity.git`, then run `git push -u origin main`.
3. Inspect the Actions run for that exact commit. Require successful Linux and Windows jobs and check the configured macOS job. Review job-specific skips. Fix failures and repeat on the new commit. Enable private vulnerability reporting or establish a private contact method.
4. On the passing commit, run `git status --short` and `git rev-parse HEAD`. Rebuild with `python -m build` in a fresh checkout. Install both artifacts separately and repeat the CLI smoke tests. Record their SHA-256 digests (`Get-FileHash dist/* -Algorithm SHA256` in PowerShell). Update release notes with only verified results.
5. Create the tag with `git tag -a v0.1.0 -m "Research Data Integrity Monitor 0.1.0"`, then `git push origin v0.1.0`. Verify the tagged commit with `git rev-list -n 1 v0.1.0` and check the remote tag's Actions results. Create a GitHub release from that tag with the tested artifacts, checksums, changelog, and known limitations. Confirm the published tag, commit, files, and download checksums.

Until a remote run completes, hosted CI and the release remain unverified. The MIT license is included. No real monitoring or external security assessment was performed. [Limitations](limitations.md)
