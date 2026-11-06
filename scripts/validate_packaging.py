#!/usr/bin/env python3
"""Validates Homebrew and Scoop manifests against a release artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOMEBREW = ROOT / "packaging" / "homebrew" / "commitguard.rb"
SCOOP = ROOT / "packaging" / "scoop" / "commitguard.json"


def _version() -> str:
    match = re.search(
        r'__version__\s*=\s*"([^"]+)"',
        (ROOT / "core" / "__init__.py").read_text(encoding="utf-8"),
    )
    if match is None:
        raise SystemExit("could not read core.__version__")
    return match.group(1)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=None)
    parser.add_argument("--artifact", type=Path, default=None)
    args = parser.parse_args(argv)

    expected = args.version or _version()
    current = _version()
    errors: list[str] = []
    if expected != current:
        errors.append(f"requested version {expected} != core.__version__ {current}")

    formula = HOMEBREW.read_text(encoding="utf-8")
    manifest = json.loads(SCOOP.read_text(encoding="utf-8"))
    if f"commit-guard-{expected}.tar.gz" not in formula:
        errors.append(f"Homebrew formula does not reference version {expected}")
    if manifest.get("version") != expected:
        errors.append(
            f"Scoop version {manifest.get('version')!r} != {expected!r}"
        )
    if manifest.get("extract_dir") != f"commit-guard-{expected}":
        errors.append("Scoop extract_dir does not match the version")
    if f"commit-guard-{expected}.tar.gz" not in str(manifest.get("url", "")):
        errors.append(f"Scoop URL does not reference version {expected}")

    homebrew_hash = re.search(r'sha256 "([0-9a-f]{64})"', formula)
    scoop_hash = str(manifest.get("hash") or "")
    if args.artifact is not None:
        artifact = args.artifact.expanduser().resolve()
        if not artifact.is_file():
            errors.append(f"artifact not found: {artifact}")
        else:
            digest = _digest(artifact)
            if homebrew_hash is None or homebrew_hash.group(1) != digest:
                errors.append("Homebrew sha256 does not match the artifact")
            if scoop_hash != digest:
                errors.append("Scoop hash does not match the artifact")
    else:
        if homebrew_hash is None or "REPLACE_WITH" in formula:
            print(
                "warning: Homebrew SHA-256 is a placeholder; "
                "pass --artifact before publishing",
                file=sys.stderr,
            )
        if not re.fullmatch(r"[0-9a-f]{64}", scoop_hash):
            print(
                "warning: Scoop hash is a placeholder; "
                "pass --artifact before publishing",
                file=sys.stderr,
            )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"packaging manifests valid for {expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
