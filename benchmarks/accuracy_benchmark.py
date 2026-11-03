#!/usr/bin/env python3
"""Fixed-commit accuracy gate for the supported CWE subset.

The harness scans one repository containing vulnerable files and one containing
the corresponding fixed files.  It fails when a stable rule misses a seeded
vulnerability (recall) or fires on the fixed counterpart (false positive).
"""

# commit-guard-ignore-file: intentionally vulnerable accuracy corpus

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"


@dataclass(frozen=True)
class AccuracyCase:
    name: str
    rule_id: str
    cwe: str
    vulnerable: dict[str, str]
    fixed: dict[str, str]


CASES: tuple[AccuracyCase, ...] = (
    AccuracyCase(
        name="python-sqli",
        rule_id="cg-python-ast-sqli-taint",
        cwe="CWE-89",
        vulnerable={
            "app.py": (
                "def lookup(request, cursor):\n"
                "    user_id = request.args.get('id')\n"
                "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
                "    cursor.execute(query)\n"
            )
        },
        fixed={
            "app.py": (
                "def lookup(request, cursor):\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
            )
        },
    ),
    AccuracyCase(
        name="python-shell",
        rule_id="cg-python-ast-shell-taint",
        cwe="CWE-78",
        vulnerable={
            "shell.py": (
                "import subprocess\n"
                "\n"
                "def run(request):\n"
                "    target = request.args.get('target')\n"
                "    subprocess.run('ping ' + target, shell=True)\n"
            )
        },
        fixed={
            "shell.py": (
                "import subprocess\n"
                "\n"
                "def run(request):\n"
                "    target = request.args.get('target')\n"
                "    subprocess.run(['ping', target], shell=False)\n"
            )
        },
    ),
    AccuracyCase(
        name="python-ssrf",
        rule_id="cg-python-ast-ssrf-taint",
        cwe="CWE-918",
        vulnerable={
            "fetch.py": (
                "import requests\n"
                "\n"
                "def fetch(request):\n"
                "    url = request.args.get('url')\n"
                "    return requests.get(url)\n"
            )
        },
        fixed={
            "fetch.py": (
                "import requests\n"
                "\n"
                "def fetch(request):\n"
                "    request.args.get('url')\n"
                "    return requests.get('https://api.example.com/data')\n"
            )
        },
    ),
    AccuracyCase(
        name="python-path-traversal",
        rule_id="cg-python-ast-path-traversal-taint",
        cwe="CWE-22",
        vulnerable={
            "files.py": (
                "def read(request):\n"
                "    name = request.args.get('name')\n"
                "    with open(name) as handle:\n"
                "        return handle.read()\n"
            )
        },
        fixed={
            "files.py": (
                "def read(request):\n"
                "    request.args.get('name')\n"
                "    with open('/var/app/data.txt') as handle:\n"
                "        return handle.read()\n"
            )
        },
    ),
    AccuracyCase(
        name="python-xss",
        rule_id="cg-python-ast-xss-taint",
        cwe="CWE-79",
        vulnerable={
            "render.py": (
                "from flask import render_template_string\n"
                "\n"
                "def render(request):\n"
                "    name = request.args.get('name')\n"
                "    return render_template_string('<p>' + name + '</p>')\n"
            )
        },
        fixed={
            "render.py": (
                "from flask import render_template_string\n"
                "\n"
                "def render(request):\n"
                "    request.args.get('name')\n"
                "    return render_template_string('<p>hello</p>')\n"
            )
        },
    ),
    AccuracyCase(
        name="javascript-code-exec",
        rule_id="cg-js-ast-code-exec-taint",
        cwe="CWE-95",
        vulnerable={
            "app.js": (
                "function run(req, res) {\n"
                "  const body = req.body.code;\n"
                "  eval(body);\n"
                "}\n"
            )
        },
        fixed={
            "app.js": (
                "function run(req, res) {\n"
                "  const body = req.body.code;\n"
                "  JSON.parse(body);\n"
                "}\n"
            )
        },
    ),
    AccuracyCase(
        name="python-cross-file-wrapper",
        rule_id="cg-python-ast-sqli-taint",
        cwe="CWE-89",
        vulnerable={
            "db.py": (
                "def run_query(cursor, request):\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n"
            ),
            "app.py": (
                "from db import run_query\n"
                "\n"
                "def view(request, cursor):\n"
                "    run_query(cursor, request)\n"
            ),
        },
        fixed={
            "db.py": (
                "def run_query(cursor, request):\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
            ),
            "app.py": (
                "from db import run_query\n"
                "\n"
                "def view(request, cursor):\n"
                "    run_query(cursor, request)\n"
            ),
        },
    ),
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=str(repo), check=True, text=True, capture_output=True
    )


def _write_tree(repo: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _scan(repo: Path, report: Path) -> list[dict]:
    command = [
        sys.executable,
        str(MAIN),
        "--repo",
        str(repo),
        "--all",
        "--threshold",
        "info",
        "--format",
        "json",
        "--report-path",
        str(report),
        "--soft-fail",
        "--quiet",
        "--no-baseline",
    ]
    subprocess.run(command, cwd=str(repo), check=False, text=True, capture_output=True)
    payload = json.loads(report.read_text(encoding="utf-8"))
    findings = payload.get("findings", [])
    return [item for item in findings if isinstance(item, dict)]


def run(*, verbose: bool = False) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="commitguard-accuracy-") as directory:
        base = Path(directory)
        vulnerable_repo = base / "vulnerable"
        fixed_repo = base / "fixed"
        vulnerable_files: dict[str, str] = {}
        fixed_files: dict[str, str] = {}
        for case in CASES:
            for name, content in case.vulnerable.items():
                vulnerable_files.setdefault(name, "")
                vulnerable_files[name] += content + "\n"
            for name, content in case.fixed.items():
                fixed_files.setdefault(name, "")
                fixed_files[name] += content + "\n"
        results: list[dict[str, object]] = []
        for repo, files, expect in (
            (vulnerable_repo, vulnerable_files, True),
            (fixed_repo, fixed_files, False),
        ):
            repo.mkdir()
            _write_tree(repo, files)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "accuracy@example.invalid")
            _git(repo, "config", "user.name", "CommitGuard Accuracy")
            _git(repo, "add", ".")
            findings = _scan(repo, base / f"{repo.name}.json")
            detected = {str(item.get("rule_id", "")) for item in findings}
            for case in CASES:
                found = case.rule_id in detected
                results.append(
                    {
                        "case": case.name,
                        "cwe": case.cwe,
                        "rule_id": case.rule_id,
                        "expected": "detected" if expect else "clean",
                        "passed": found if expect else not found,
                    }
                )
        passed = sum(1 for item in results if item["passed"])
        payload = {
            "cases": len(CASES),
            "checks": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "results": results,
            "suite_passed": passed == len(results),
        }
        if verbose:
            for item in results:
                status = "PASS" if item["passed"] else "FAIL"
                print(f"{status} {item['case']:<28} {item['expected']}")
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
            f"{payload['passed']}/{payload['checks']} accuracy checks passed "
            f"({payload['cases']} fixed-commit cases)."
        )
    return 0 if payload["suite_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
