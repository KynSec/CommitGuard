#!/usr/bin/env python3
"""Signs an offline OSV snapshot with an HMAC-SHA256 sidecar.

Set COMMITGUARD_OSV_SIGNING_KEY (or pass --key-env) before signing. The key is
read from the environment so it never appears in shell history or process
listings.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.sca import (
    SIGNING_KEY_ENV,
    SCAError,
    sign_snapshot,
    verify_snapshot_signature,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "snapshot",
        type=Path,
        nargs="?",
        default=Path(".commit_guard_osv.json"),
    )
    parser.add_argument("--key-env", default=SIGNING_KEY_ENV)
    args = parser.parse_args(argv)
    key = os.environ.get(args.key_env, "")
    try:
        signature = sign_snapshot(args.snapshot, key=key or None)
        valid, reason = verify_snapshot_signature(
            args.snapshot, key=key or None, required=True  # commit-guard-ignore: generic-api-key
        )
    except SCAError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not valid:
        print(f"error: {reason}", file=sys.stderr)
        return 2
    print(f"Signed {args.snapshot} -> {signature} ({reason})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
