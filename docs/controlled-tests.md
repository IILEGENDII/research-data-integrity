# Controlled verification

Run `python -m pytest -q -s tests/test_scenarios.py` after installing the development extra. To repeat one case, append its bracketed ID to the test function, for example `python -m pytest -q -s "tests/test_scenarios.py::test_scenario[same-size]"`. Each row below names the exact ID. Pytest exits zero when the assertions pass. The exit column is the return value of the installed application's CLI function.

Each case begins with fresh synthetic files containing four and three bytes. The fixture calls `keygen` and signed `baseline`, then invokes `verify ROOT --manifest BASE --public-key PUBLIC --format json`. It supplies a disposable passphrase through a test double for the terminal prompt. Authentication, hashing, JSON, filesystem reads, and signature validation use the actual implementation.

| Case | Change and expected category | Windows observation | CLI exit |
| --- | --- | --- | ---: |
| clean | Original files, unchanged | unchanged | 0 |
| replace | Write longer content, modified | modified | 1 |
| same-size | Reverse four bytes, modified | modified | 1 |
| add | Create a binary file, added | added | 1 |
| delete | Remove a checkpoint, missing | missing | 1 |
| tamper | Edit a recorded digest, signature_invalid | signature_invalid | 3 |
| wrong-key | Supply a different public key, signature_invalid | signature_invalid | 3 |
| traversal | Insert a parent traversal, input_error | input_error | 2 |
| symlink | Add a file link, unsupported | skipped: account lacks file-symlink privilege | — |
| mid-read | Append a byte during digest update, unstable | unstable | 2 |

All ten cases ran on local Ubuntu. The nine shared cases produced the Windows observations above. The file symlink on Ubuntu produced `unsupported`, exit 2, without following it. The mid-read case uses a deterministic hook to time a real append to a disposable file. The two trust-failure cases and the traversal case also assert zero bytes read and an empty findings array. [Scenario implementation](../tests/test_scenarios.py)
