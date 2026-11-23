import os
import select
import subprocess
import sys
import time

import pytest


def interactive(args, prompts):
    master, slave = os.openpty()
    try:
        with subprocess.Popen(
            [sys.executable, "-m", "research_integrity", *args],
            stdin=slave,
            stderr=slave,
            stdout=subprocess.PIPE,
            start_new_session=True,
        ) as proc:
            try:
                for prompt in prompts:
                    deadline = time.monotonic() + 15
                    buffer = b""
                    while prompt not in buffer:
                        remaining = max(0, deadline - time.monotonic())
                        assert select.select([master], [], [], remaining)[0], (
                            "terminal prompt timed out"
                        )
                        buffer += os.read(master, 4096)
                    os.write(master, b"ephemeral terminal fixture\n")
                out, _ = proc.communicate(timeout=15)
                assert proc.returncode == 0
                return out.decode()
            finally:
                if proc.poll() is None:
                    proc.kill()
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX pseudo-terminal")
def test_signed_terminal_workflow(tmp_path):
    root = tmp_path / "demo"

    def cli(*args, expected=0):
        result = subprocess.run(
            [sys.executable, "-I", "-m", "research_integrity", *map(str, args)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == expected, result.stderr
        return result.stdout

    cli("demo", "--output", root)
    public = str(root / "keys" / "public.pem")
    private = str(root / "keys" / "private.pem")
    manifest = str(root / "control" / "base.json")
    data = str(root / "data")
    assert "fingerprint" in interactive(
        ["keygen", "--private-key", private, "--public-key", public],
        [b"Signing passphrase:", b"Confirm passphrase:"],
    )
    assert "SIGNED" in interactive(
        ["baseline", data, "--output", manifest, "--sign-key", private],
        [b"Signing passphrase:"],
    )
    args = ["verify", data, "--manifest", manifest, "--public-key", public]
    clean = cli(*args)
    assert "VERIFIED" in clean and "Unchanged: 3" in clean
    with (root / "data" / "inputs" / "material.csv").open("ab") as stream:
        stream.write(b"C,1.75\n")
    modified = cli(*args, expected=1)
    assert "MODIFIED  inputs/material.csv" in modified
    print(clean + modified)
