#!/usr/bin/env python3
"""Published evaluation for the local-first AI assistant.

The evaluation is deterministic and offline.  It checks that:

* each supported finding category receives actionable remediation guidance;
* explanations are stable across runs;
* secret values never appear in a context package or explanation;
* the context package respects its size bound.

Run ``python benchmarks/ai_evaluation.py --json`` to produce the artifact used
by the public leaderboard.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.ai_assistant import (
    build_context_package,
    context_from_finding,
    explain_finding,
    resolve_provider,
)
from core.scanner import Finding


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    finding: Finding
    expected_keywords: tuple[str, ...]
    secret: str = ""


CASES: tuple[EvaluationCase, ...] = (
    EvaluationCase(
        name="secret-rotation",
        finding=Finding(
            file="app.py",
            line_number=12,
            rule_id="gitleaks-aws-access-token",
            description="AWS access token detected.",
            severity="critical",
            source="gitleaks",
            flagged_code='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
            redacted_code='aws_access_key_id = "AK********LE"',
            category="secret",
            tags=("secret", "aws"),
            cwe="CWE-798",
        ),
        expected_keywords=("Rotate", "history"),
        secret="AKIAIOSFODNN7EXAMPLE",
    ),
    EvaluationCase(
        name="dependency-upgrade",
        finding=Finding(
            file="requirements.txt",
            line_number=3,
            rule_id="sca-CVE-2024-0001",
            description="Vulnerable dependency.",
            severity="high",
            source="sca",
            flagged_code="requests==2.19.0",
            category="dependency",
            cwe="CWE-1104",
            fixed_versions=("2.32.0",),
        ),
        expected_keywords=("Upgrade", "2.32.0"),
    ),
    EvaluationCase(
        name="sast-validation",
        finding=Finding(
            file="views.py",
            line_number=40,
            rule_id="cg-python-ast-sqli-taint",
            description="Request data reaches a SQL sink.",
            severity="high",
            source="python_ast",
            flagged_code="cursor.execute(query)",
            category="sast",
            tags=("sqli", "taint"),
            cwe="CWE-89",
        ),
        expected_keywords=("Validate", "sink"),
    ),
    EvaluationCase(
        name="injection-parameterization",
        finding=Finding(
            file="db.py",
            line_number=8,
            rule_id="cg-sqli",
            description="String-built query.",
            severity="high",
            source="custom",
            flagged_code='query = "SELECT * FROM t WHERE id=" + user_id',
            category="injection",
            cwe="CWE-89",
        ),
        expected_keywords=("parameterized", "untrusted"),
    ),
    EvaluationCase(
        name="iac-hardening",
        finding=Finding(
            file="main.tf",
            line_number=21,
            rule_id="cg-iac-public-bucket",
            description="Bucket allows public access.",
            severity="medium",
            source="iac",
            flagged_code='acl = "public-read"',
            category="iac",
            cwe="CWE-284",
        ),
        expected_keywords=("Harden", "pin"),
    ),
)


def _evaluate_case(case: EvaluationCase) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    context = context_from_finding(case.finding)
    provider = resolve_provider("local")
    first = provider.explain(context)
    second = provider.explain(context)
    explanation = explain_finding(case.finding)
    package = build_context_package(".", (case.finding,), max_chars=12000)
    markdown = package.to_markdown()
    serialized = json.dumps(package.to_dict())
    combined = f"{first}\n{explanation}\n{markdown}\n{serialized}"

    checks.append(
        {
            "case": case.name,
            "check": "stable-explanation",
            "passed": first == second,
            "detail": "local provider output is deterministic",
        }
    )
    for keyword in case.expected_keywords:
        checks.append(
            {
                "case": case.name,
                "check": f"guidance:{keyword}",
                "passed": keyword.lower() in combined.lower(),
                "detail": f"expected guidance keyword '{keyword}'",
            }
        )
    checks.append(
        {
            "case": case.name,
            "check": "bounded-context",
            "passed": len(markdown) <= 12000 and not package.truncated,
            "detail": f"{len(markdown)} characters",
        }
    )
    if case.secret:
        checks.append(
            {
                "case": case.name,
                "check": "secret-redacted",
                "passed": case.secret not in combined,
                "detail": "secret value must not appear in AI output",
            }
        )
    checks.append(
        {
            "case": case.name,
            "check": "remediation-present",
            "passed": bool(package.findings and package.findings[0].remediation),
            "detail": "remediation guidance is non-empty",
        }
    )
    return checks


def run(*, verbose: bool = False) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    for case in CASES:
        checks.extend(_evaluate_case(case))
    passed = sum(1 for check in checks if check["passed"])
    payload: dict[str, object] = {
        "suite": "ai-evaluation",
        "provider": "local",
        "cases": len(CASES),
        "checks": len(checks),
        "passed": passed,
        "failed": len(checks) - passed,
        "suite_passed": passed == len(checks),
        "results": checks,
    }
    if verbose:
        for check in checks:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"{status} {check['case']:<28} {check['check']}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    payload = run(verbose=not args.quiet and not args.json)
    text = json.dumps(payload, indent=2) + "\n"
    if args.output:
        args.output.expanduser().write_text(text, encoding="utf-8")
    if args.json:
        print(text, end="")
    elif args.quiet:
        print(
            f"{payload['passed']}/{payload['checks']} AI evaluation checks passed "
            f"({payload['cases']} cases)."
        )
    return 0 if payload["suite_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
