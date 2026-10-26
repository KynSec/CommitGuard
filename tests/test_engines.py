from __future__ import annotations

import re
import time
import unittest

from core.engines import (
    EngineCapability,
    EngineResult,
    RegexEngine,
    Registry,
    Runner,
    ScanContext,
    TaintEngine,
    dedupe_findings,
    stable_order,
)
from core.git_diff import DiffLine
from core.rule_loader import Rule
from core.scanner import Finding


def make_rule() -> Rule:
    return Rule(
        rule_id="test-secret",
        description="test secret",
        severity="high",
        pattern=re.compile(r'API_KEY\s*=\s*"([^"]+)"'),
        source="gitleaks",
        secret_group=1,
        is_secret=True,
    )


def make_finding(**overrides) -> Finding:
    payload = {
        "file": "app.py",
        "line_number": 1,
        "rule_id": "test-secret",
        "description": "secret",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": 'API_KEY = "secretvalue123"',
        "redacted_code": 'API_KEY = "se********23"',
        "fingerprint": "aaaaaaaaaaaaaaaa",
        "tags": ("secret",),
        "cwe": "CWE-798",
    }
    payload.update(overrides)
    return Finding(**payload)


class FakeEngine:
    def __init__(self, name, result=None, *, sleep=0.0, error=None):
        self.name = name
        self.result = result
        self.sleep = sleep
        self.error = error

    def capability(self):
        return EngineCapability(name=self.name, categories=frozenset({"secret"}))

    def available(self):
        return True, "fake"

    def run(self, context):
        if self.sleep:
            time.sleep(self.sleep)
        if self.error:
            raise RuntimeError(self.error)
        return self.result or EngineResult(engine=self.name)


class EngineTests(unittest.TestCase):
    def test_registry_and_capabilities(self):
        registry = Registry()
        registry.register(FakeEngine("fake"))
        self.assertEqual(registry.names(), ("fake",))
        self.assertEqual(registry.selected()[0].name, "fake")
        self.assertEqual(registry.capabilities()[0].name, "fake")
        with self.assertRaises(KeyError):
            registry.selected(["missing"])

    def test_regex_engine_normalizes_schema(self):
        context = ScanContext(
            repo_root=__import__("pathlib").Path("."),
            diff_lines=(DiffLine("app.py", 1, 'API_KEY = "secretvalue123"'),),
            changed_paths=("app.py",),
            rules=(make_rule(),),
        )
        result = RegexEngine().run(context)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.engine, "regex")
        self.assertEqual(finding.category, "secret")
        self.assertEqual(finding.schema_version, 3)

    def test_taint_engine_adds_flow(self):
        source = (
            "def lookup(request, cursor):\n"
            "    user_id = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "    cursor.execute(query)\n"
        ).splitlines()
        context = ScanContext(
            repo_root=__import__("pathlib").Path("."),
            diff_lines=(
                DiffLine("app.py", 2, "user_id = request.args.get('id')"),
            ),
            changed_paths=("app.py",),
            files={"app.py": source},
            file_lines={"app.py": source},
        )
        result = TaintEngine().run(context)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.engine, "ast")
        self.assertEqual(finding.confidence, "high")
        self.assertTrue(finding.code_flows)

    def test_runner_isolates_failures(self):
        registry = Registry()
        registry.register(FakeEngine("broken", error="boom"))
        registry.register(FakeEngine("good", EngineResult(findings=(make_finding(),), engine="good")))
        report = Runner(registry, workers=2).run(
            ScanContext(repo_root=__import__("pathlib").Path(".")),
            names=("broken", "good"),
        )
        self.assertEqual(len(report.findings), 1)
        self.assertTrue(any("boom" in error for error in report.errors))
        self.assertIn("good", report.engines)

    def test_runner_timeout_is_a_warning(self):
        registry = Registry()
        registry.register(FakeEngine("slow", sleep=0.2))
        report = Runner(registry, workers=2).run(
            ScanContext(repo_root=__import__("pathlib").Path("."), engine_timeout=0.01)
        )
        self.assertTrue(report.cancelled)
        self.assertTrue(any("timed out" in warning for warning in report.warnings))
        self.assertEqual(report.findings, ())

    def test_runner_dedupes_and_records_sources(self):
        left = make_finding(source="gitleaks", fix={"description": "fix"})
        right = make_finding(source="semgrep", fingerprint="bbbbbbbbbbbbbbbb")
        registry = Registry()
        registry.register(FakeEngine("regex", EngineResult(findings=(left,), engine="regex")))
        registry.register(FakeEngine("semgrep", EngineResult(findings=(right,), engine="semgrep")))
        report = Runner(registry, workers=1).run(
            ScanContext(repo_root=__import__("pathlib").Path(".")),
            names=("regex", "semgrep"),
        )
        self.assertEqual(len(report.findings), 1)
        merged = report.findings[0]
        self.assertIsNotNone(merged.fix)
        self.assertIn("semgrep", merged.also_reported_by)

    def test_dedupe_does_not_merge_categories(self):
        secret = make_finding(fingerprint="1" * 16)
        sast = make_finding(
            rule_id="sast-rule",
            source="python_ast",
            tags=("sast",),
            cwe="CWE-89",
            fingerprint="2" * 16,
        )
        self.assertEqual(len(dedupe_findings([secret, sast])), 2)

    def test_stable_order_is_deterministic(self):
        low = make_finding(severity="low", fingerprint="3" * 16)
        high = make_finding(severity="high", fingerprint="4" * 16)
        ordered = stable_order([low, high])
        self.assertEqual(ordered[0].severity, "high")


if __name__ == "__main__":
    unittest.main()
