# Contributing

Create a virtual environment with Python 3.11 or newer, activate it, and run these commands from the checkout:

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest -q -rs
python -m research_integrity --help
python -m build
```

Use disposable local fixtures. A test involving a refused path should create only the minimum synthetic input needed and assert the exit code, reported uncertainty, and lack of unintended output. Document platform capability skips with their actual reason. Use focused functions and ordinary Python names. Explain reasoning when a path, trust, or filesystem decision is easy to misread.

Keep changes within local inventory, signing, verification, and reporting. Retain default refusal of unsigned data, no-clobber output, and read-only dataset operations. Use the private reporting process for security defects. [Security policy](SECURITY.md)
