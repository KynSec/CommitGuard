#!/usr/bin/env python3
"""Verifies release checksums and an optional detached signature offline.

Usage:
    python scripts/verify_release.py dist --public-key release-public.pem
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path


def _parse_checksums(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        if not (len(digest) == 64 and name):
            raise SystemExit(f"malformed checksum line: {line!r}")
        entries.append((digest.lower(), name))
    return entries


def verify(directory: Path, *, public_key: Path | None, require_signature: bool) -> int:
    checksums = directory / "SHA256SUMS"
    if not checksums.is_file():
        raise SystemExit(f"missing checksum file: {checksums}")
    failures = 0
    for expected, name in _parse_checksums(checksums):
        target = directory / name
        if not target.is_file():
            print(f"MISSING {name}")
            failures += 1
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if not actual == expected:
            print(f"MISMATCH {name}")
            failures += 1
        else:
            print(f"OK {name}")

    signature = directory / "SHA256SUMS.sig"
    if signature.is_file():
        if public_key is None:
            message = "signature present but --public-key was not supplied"
            print(f"SKIP {message}")
            if require_signature:
                failures += 1
        else:
            result = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    str(signature),
                    str(checksums),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                print("OK SHA256SUMS.sig")
            else:
                print(f"INVALID SHA256SUMS.sig: {result.stderr.strip()}")
                failures += 1
    elif require_signature:
        print("MISSING SHA256SUMS.sig")
        failures += 1

    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--public-key", type=Path, default=None)
    parser.add_argument("--require-signature", action="store_true")
    args = parser.parse_args(argv)
    return verify(
        args.directory,
        public_key=args.public_key,
        require_signature=args.require_signature,
    )


if __name__ == "__main__":
    sys.exit(main())
