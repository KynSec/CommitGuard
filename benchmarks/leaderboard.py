#!/usr/bin/env python3
"""Builds the public CommitGuard benchmark leaderboard from result artifacts.

Inputs are the JSON files produced by ``accuracy_benchmark.py``,
``ai_evaluation.py``, and ``scan_benchmark.py``.  The output is deterministic
Markdown plus a machine-readable JSON document so an independent party can
reproduce every row.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SUITES = ("accuracy", "ai-evaluation", "scan-benchmark")


@dataclass(frozen=True)
class Row:
    suite: str
    tool: str
    version: str
    passed: int
    checks: int
    metric: str
    value: float
    artifact: str

    @property
    def pass_rate(self) -> float:
        return self.passed / self.checks if self.checks else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "tool": self.tool,
            "version": self.version,
            "passed": self.passed,
            "checks": self.checks,
            "pass_rate": round(self.pass_rate, 4),
            "metric": self.metric,
            "value": self.value,
            "artifact": self.artifact,
        }


def _suite_name(payload: dict[str, Any], path: Path) -> str:
    explicit = str(payload.get("suite") or "")
    if explicit:
        return explicit
    if "median_ms" in payload:
        return "scan-benchmark"
    if "cases" in payload and "checks" in payload:
        return "ai-evaluation" if "provider" in payload else "accuracy"
    return path.stem


def _row_from_payload(
    payload: dict[str, Any],
    path: Path,
    *,
    tool: str,
    version: str,
) -> Row | None:
    suite = _suite_name(payload, path)
    if suite == "scan-benchmark":
        median = float(payload.get("median_ms") or 0.0)
        passed = 1 if bool(payload.get("passed", True)) else 0
        return Row(
            suite=suite,
            tool=tool,
            version=version,
            passed=passed,
            checks=1,
            metric="median_ms",
            value=median,
            artifact=str(path),
        )
    checks = int(payload.get("checks") or 0)
    passed = int(payload.get("passed") or 0)
    if checks == 0:
        return None
    return Row(
        suite=suite,
        tool=tool,
        version=version,
        passed=passed,
        checks=checks,
        metric="checks",
        value=round(passed / checks, 4),
        artifact=str(path),
    )


def collect(
    paths: list[Path],
    *,
    tool: str = "CommitGuard",
    version: str = "unknown",
) -> list[Row]:
    rows: list[Row] = []
    for path in paths:
        if path.is_dir():
            candidates = sorted(path.glob("*.json"))
        else:
            candidates = [path]
        for candidate in candidates:
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            row = _row_from_payload(payload, candidate, tool=tool, version=version)
            if row is not None:
                rows.append(row)
    rows.sort(key=lambda row: (SUITES.index(row.suite) if row.suite in SUITES else 99, row.tool, row.version))
    return rows


def render_markdown(rows: list[Row], *, metadata: dict[str, str]) -> str:
    lines = [
        "# CommitGuard benchmark leaderboard",
        "",
        "Reproducible results only. Every row names the JSON artifact that produced it.",
        "",
        "## Environment",
        "",
    ]
    for key, value in metadata.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Suite | Tool | Version | Pass rate | Metric | Artifact |",
            "|---|---|---|---|---|---|",
        ]
    )
    for row in rows:
        rate = f"{row.passed}/{row.checks} ({row.pass_rate:.0%})"
        lines.append(
            f"| {row.suite} | {row.tool} | {row.version} | {rate} | "
            f"{row.metric}={row.value} | `{row.artifact}` |"
        )
    if not rows:
        lines.append("| _no artifacts found_ | | | | | |")
    lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```bash",
            "python benchmarks/accuracy_benchmark.py --json --output accuracy.json",
            "python benchmarks/ai_evaluation.py --json --output ai-evaluation.json",
            "python benchmarks/scan_benchmark.py --json --output scan-benchmark.json",
            "python benchmarks/leaderboard.py --results-dir . --output leaderboard.md",
            "```",
            "",
            "The leaderboard does not compare against commercial products and does not",
            "claim whole-program precision. See [BENCHMARKS.md](../docs/BENCHMARKS.md).",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="*", type=Path, help="Result JSON files or directories.")
    parser.add_argument("--results-dir", type=Path, default=None)
    parser.add_argument("--tool", default="CommitGuard")
    parser.add_argument("--version", default=None)
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    paths = list(args.results)
    if args.results_dir is not None:
        paths.append(args.results_dir)
    if not paths:
        parser.error("provide at least one result file or --results-dir")

    version = args.version
    if version is None:
        try:
            from core import __version__

            version = __version__
        except (ImportError, AttributeError):
            version = "unknown"
    rows = collect(paths, tool=args.tool, version=version)
    metadata = {
        "commit": args.commit,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    if args.format == "json":
        text = (
            json.dumps(
                {
                    "metadata": metadata,
                    "rows": [row.to_dict() for row in rows],
                },
                indent=2,
            )
            + "\n"
        )
    else:
        text = render_markdown(rows, metadata=metadata)
    if args.output:
        args.output.expanduser().write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
