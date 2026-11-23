# Design decisions

**Compare bytes on every run.** Each file is read in blocks of up to 4 MiB. Length and timestamp checks alone can miss edits. File identity, type, length, and modification time are compared across discovery, open, and completion. POSIX also checks change time. Windows descriptor and path APIs can report different change-time semantics.

**Authenticate before comparison.** The verifier parses a bounded, versioned JSON document and checks its signature using the caller's trusted key. It builds a new inventory from directory enumeration. This keeps a manifest's path strings out of filesystem open calls and makes additions visible.

**Keep baselines immutable at the CLI.** Baselines and named reports require fresh names. The writer flushes and syncs a temporary sibling, then publishes with a no-replace operation. Separate publication prevents an interrupted file write from exposing partial JSON as a completed baseline. Keypair publication uses two file operations. After a failure or interruption, inspect both destinations before retrying.

**Record uncertainty separately.** Files that could be hashed get findings. Unsupported entries and failures go into the error array, with a relative path when available. A rename appears as one missing and one added path. A disappearing directory can hide other files, so its children cannot reliably be marked absent.

**Make result codes useful to scripts.** Trust failure (3) takes priority, then incomplete checks (2), then complete comparisons with differences (1), then clean (0). Text suppresses unchanged rows. JSON retains those rows as well as distinct errors and totals. `files_scanned` counts completed hashes. `bytes_read` includes successfully read dataset bytes even if the file is later rejected as unstable. A manifest rejected before scanning has zero scanned files and zero dataset bytes read.
