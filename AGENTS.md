# Repository conventions

Work with explicitly selected local datasets and disposable synthetic fixtures. Keep private keys, live manifests, and research data out of version control. Do not contact external targets or university infrastructure.

Authenticate before traversing a dataset. Never open a dataset filename supplied by a manifest. Keep manifests, trusted keys, and reports outside the monitored tree. Preserve no-clobber publication and distinct exit statuses for differences, incomplete reads, and trust failures.

Use direct names and small functions. Comments should explain reasoning. Run Ruff lint and format checks, the full pytest suite with skip reasons, and the installed CLI after changing behavior. Recheck clean artifact installs when packaging changes. Report observed results, platform skips, and any unrun release checks.
