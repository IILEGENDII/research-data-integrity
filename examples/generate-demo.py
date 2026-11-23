"""Create the same synthetic dataset as the installed demo command."""

import sys

from research_integrity.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["demo", *sys.argv[1:]]))
