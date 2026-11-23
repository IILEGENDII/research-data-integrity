# Synthetic evaluation

The controlled suite exercises explicit changes to known files. It can demonstrate detection of those changes and rejection of a modified baseline. It does not measure detection frequency in operational research datasets. A clean comparison to a compromised baseline can be misleading. An update made intentionally by the researcher still counts as a difference. [Procedure and observed outcomes](controlled-tests.md)

## Streaming cost

From an installed checkout run `python examples/benchmark.py 4 16 64`. The script writes and scans one temporary file per size. It times inventory alone with a monotonic performance counter. The peak is Python-tracked allocations during inventory, excluding native allocator overhead, filesystem caches and fixture creation.

One Windows AMD64 run with CPython 3.14.7 and 4 MiB reads measured the following. These are single, recently written files and wall times can vary with the filesystem cache.

| Bytes hashed | Seconds | MiB/s | Peak traced bytes |
| ---: | ---: | ---: | ---: |
| 4,194,304 | 0.024659 | 162.21 | 4,339,117 |
| 16,777,216 | 0.052283 | 306.03 | 8,528,072 |
| 67,108,864 | 0.149955 | 426.79 | 8,527,752 |

The two larger files had nearly identical peak traced allocation. The inventory retains records for filenames and hashes, so increasing file count has a different memory cost. For a bounded-read assertion independent of machine speed, run `python -m pytest -q tests/test_inventory.py -k bounded_reads`.
