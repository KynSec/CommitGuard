#!/usr/bin/env python3
"""Builds standalone CommitGuard binaries with PyInstaller.

PyInstaller is an optional build dependency.  This script fails with a clear
message instead of silently producing a zipapp when it is missing.  CI uses it
to publish per-platform binaries so users without Python can run the gate.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "main.py"
DATA_DIRECTORIES = ("rules", "docs")


def _pyinstaller_available() -> bool:
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def build_command(
    output_dir: Path,
    *,
    name: str,
    onefile: bool,
    console: bool,
    clean: bool,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--name",
        name,
        "--distpath",
        str(output_dir),
        "--workpath",
        str(output_dir / "build"),
        "--specpath",
        str(output_dir / "spec"),
    ]
    if onefile:
        command.append("--onefile")
    if console:
        command.append("--console")
    if clean:
        command.append("--clean")
    command.extend(["--collect-all", "yaml"])
    for directory in DATA_DIRECTORIES:
        source = ROOT / directory
        if source.is_dir():
            command.extend(
                ["--add-data", f"{source}{os.pathsep}{directory}"]
            )
    command.append(str(ENTRYPOINT))
    return command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "native")
    parser.add_argument("--name", default="commit-guard")
    parser.add_argument("--onedir", action="store_true", help="Build a directory instead of one file.")
    parser.add_argument("--windowed", action="store_true", help="Build without a console window.")
    parser.add_argument("--no-clean", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    output_dir = args.output_dir.expanduser().resolve()
    command = build_command(
        output_dir,
        name=args.name,
        onefile=not args.onedir,
        console=not args.windowed,
        clean=not args.no_clean,
    )
    if args.dry_run:
        print(" ".join(command))
        return 0
    if not _pyinstaller_available():
        print(
            "[commit-guard] PyInstaller is required for native binaries: "
            "python -m pip install pyinstaller",
            file=sys.stderr,
        )
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "spec").mkdir(parents=True, exist_ok=True)
    print(f"[commit-guard] Building native binary in {output_dir}")
    result = subprocess.run(command, cwd=str(ROOT), check=False)
    if result.returncode != 0:
        return result.returncode
    binary = output_dir / (args.name + (".exe" if os.name == "nt" else ""))
    if not binary.exists():
        candidate = output_dir / args.name / args.name
        binary = candidate if candidate.exists() else binary
    if binary.exists():
        print(f"[commit-guard] Built {binary} ({binary.stat().st_size} bytes)")
    else:
        print(
            "[commit-guard] Build finished but the binary was not found; "
            f"inspect {output_dir}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
