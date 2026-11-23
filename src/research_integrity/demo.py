import struct
from pathlib import Path

from .storage import new_path, write_new


def create_demo(output: Path) -> None:
    output = new_path(output)
    output.mkdir(parents=True, exist_ok=False)
    files = {
        "data/inputs/material.csv": b"sample,density\nA,1.25\nB,1.50\n",
        "data/inputs/run.json": b'{"steps": 3, "spacing": 0.25}\n',
        "data/results/frame.bin": struct.pack("<4f", 0.0, 0.25, 0.50, 0.75),
        "WALKTHROUGH.txt": (
            b"These files are synthetic. Run these commands from this directory.\n"
            b"research-integrity keygen --private-key keys/private.pem --public-key keys/public.pem\n"
            b"research-integrity baseline data --output control/base.json --sign-key keys/private.pem\n"
            b"research-integrity verify data --manifest control/base.json --public-key keys/public.pem\n"
            b"Append a row to data/inputs/material.csv and repeat verify. Expect exit 1.\n"
            b"For real work, protect the public key separately and keep the signing key offline.\n"
        ),
    }
    for name, data in files.items():
        write_new(output / name, data)
