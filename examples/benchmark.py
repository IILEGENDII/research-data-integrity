"""Measure successful SHA-256 inventory reads of a generated regular file."""

import argparse
import json
import platform
import tempfile
import time
import tracemalloc
from pathlib import Path

from research_integrity.inventory import scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mib", nargs="+", type=int)
    args = parser.parse_args()
    for mib in args.mib:
        if not 1 <= mib <= 256:
            parser.error("each synthetic file must be between 1 and 256 MiB")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with (root / "synthetic.bin").open("wb") as stream:
                chunk = bytes(1024 * 1024)
                for _ in range(mib):
                    stream.write(chunk)
            tracemalloc.start()
            start = time.perf_counter()
            result = scan(root)
            elapsed = time.perf_counter() - start
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            if result.errors or result.bytes_read != mib * 1024**2:
                raise RuntimeError("Incomplete benchmark scan")
            print(
                json.dumps(
                    {
                        "bytes_read": result.bytes_read,
                        "seconds": round(elapsed, 6),
                        "MiB_per_second": round(mib / elapsed, 2),
                        "peak_python_bytes": peak,
                        "os": platform.system(),
                        "machine": platform.machine(),
                        "python": platform.python_version(),
                    }
                )
            )


if __name__ == "__main__":
    main()
