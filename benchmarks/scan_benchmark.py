#!/usr/bin/env python3
"""Deterministic staged-diff benchmark for the CommitGuard gate.

The default fixture is generated locally and contains no real secrets.  It is
intended to catch order-of-magnitude regressions in process startup, diff
selection, rule matching, deduplication, and report writing.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=str(repo), text=True, capture_output=True, check=False
    )


def build_fixture(root: Path, *, files: int = 120, lines: int = 20) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "benchmark@example.invalid")
    _git(root, "config", "user.name", "CommitGuard Benchmark")
    for index in range(files):
        package = root / "src" / f"pkg{index % 12:02d}"
        package.mkdir(parents=True, exist_ok=True)
        content = [f"# generated fixture {index}", "import os", ""]
        for line in range(lines):
            if line % 7 == 0:
                content.append(f"def function_{index}_{line}(value):")
                content.append(f"    return value + {line}")
            elif line % 11 == 0:
                content.append(f"# TODO: review value_{index}_{line}")
            else:
                content.append(f"value_{index}_{line} = os.getenv('VAR_{index}_{line}', '')")
        (package / f"module_{index:03d}.py").write_text(
            "\n".join(content) + "\n", encoding="utf-8"
        )
    _git(root, "add", ".")
    return root


def run_once(repo: Path, report_path: Path, timeout: float) -> float:
    command = [
        sys.executable,
        str(MAIN),
        "--repo",
        str(repo),
        "--threshold",
        "info",
        "--format",
        "json",
        "--report-path",
        str(report_path),
        "--soft-fail",
        "--quiet",
    ]
    started = time.perf_counter()
    result = subprocess.run(
        command, check=False, cwd=str(repo), text=True, capture_output=True, timeout=timeout
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"scan failed with {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return elapsed_ms


def benchmark(
    repo: Path,
    *,
    iterations: int = 3,
    timeout: float = 60.0,
) -> dict[str, object]:
    samples: list[float] = []
    with tempfile.TemporaryDirectory(prefix="commitguard-benchmark-") as directory:
        report = Path(directory) / "report.json"
        run_once(repo, report, timeout)  # warm the parsed-rule cache
        for _ in range(iterations):
            samples.append(run_once(repo, report, timeout))
        if report.is_file():
            payload = json.loads(report.read_text(encoding="utf-8"))
            findings = int(payload.get("total") or 0)
        else:
            findings = 0
    samples.sort()
    median = statistics.median(samples)
    return {
        "samples_ms": [round(value, 2) for value in samples],
        "median_ms": round(median, 2),
        "min_ms": round(min(samples), 2),
        "max_ms": round(max(samples), 2),
        "findings": findings,
        "iterations": iterations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=None,
                        help="Existing repo to benchmark instead of generating a fixture.")
    parser.add_argument("--files", type=int, default=120)
    parser.add_argument("--lines", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--max-median-ms", type=float, default=2000.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    with tempfile.TemporaryDirectory(prefix="commitguard-benchmark-fixture-") as temp:
        repo = args.repo.expanduser().resolve() if args.repo else build_fixture(
            Path(temp), files=args.files, lines=args.lines
        )
        try:
            result = benchmark(
                repo, iterations=args.iterations, timeout=args.timeout
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"benchmark failed: {exc}", file=sys.stderr)
            return 2
    result["max_median_ms"] = args.max_median_ms
    result["passed"] = float(result["median_ms"]) <= args.max_median_ms
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.expanduser().write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
