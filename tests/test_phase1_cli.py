from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import install_hook
from core.reporter import build_json_report
from core.scanner import Finding

FIXTURES = Path(__file__).parent / "fixtures" / "ingest"


def finding(**overrides) -> Finding:
    payload = {
        "file": "app.py",
        "line_number": 1,
        "rule_id": "cg-test",
        "description": "test",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": "test",
        "redacted_code": "test",
        "fingerprint": "aaaaaaaaaaaaaaaa",
        "tags": ("secret",),
        "cwe": "CWE-798",
    }
    payload.update(overrides)
    return Finding(**payload)


class Phase1CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Test")
        (self.root / "README.md").write_text("fixture\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-q", "-m", "init")

    def tearDown(self):
        self.temp.cleanup()

    def _git(self, *args):
        import subprocess

        subprocess.run(["git", *args], cwd=str(self.root), check=True, capture_output=True)

    def _run(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = install_hook.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def _write_report(self, findings: list[Finding]) -> Path:
        path = self.root / "report.json"
        path.write_text(build_json_report(findings, "info"), encoding="utf-8")
        return path

    def test_policy_validate_and_invalid(self):
        code, stdout, _ = self._run("policy", "validate", str(self.root), "--format", "json")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(stdout)["valid"])
        (self.root / ".commit_guard.toml").write_text(
            "[gate]\nthreshold = 'urgent'\n", encoding="utf-8"
        )
        code, _, stderr = self._run("policy", "validate", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("threshold", stderr)

    def test_gate_fails_new_high_and_allows_baseline(self):
        report = self._write_report([finding()])
        code, stdout, _ = self._run(
            "gate", "--repo", str(self.root), "--report", str(report)
        )
        self.assertEqual(code, 1)
        self.assertIn("FAILED", stdout)
        (self.root / ".commit_guard_ignore").write_text(
            "fingerprint:aaaaaaaaaaaaaaaa\n", encoding="utf-8"
        )
        code, _, _ = self._run(
            "gate", "--repo", str(self.root), "--report", str(report)
        )
        self.assertEqual(code, 0)

    def test_gate_json_and_explain(self):
        report = self._write_report([finding()])
        code, stdout, _ = self._run(
            "gate", "--repo", str(self.root), "--report", str(report), "--format", "json"
        )
        self.assertEqual(code, 1)
        payload = json.loads(stdout)
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["schema_version"], 1)
        code, stdout, _ = self._run(
            "policy",
            "explain",
            "aaaaaaaaaaaaaaaa",
            str(self.root),
            "--report",
            str(report),
        )
        self.assertEqual(code, 0)
        self.assertIn("chain", json.loads(stdout))

    def test_triage_accept_then_gate_passes(self):
        report = self._write_report([finding()])
        code, _, stderr = self._run(
            "triage",
            "accept",
            "aaaaaaaaaaaaaaaa",
            "--repo",
            str(self.root),
            "--owner",
            "@team",
            "--reason",
            "Legacy test finding with a tracked ticket.",
            "--ticket",
            "SEC-1",
            "--expires",
            "2099-01-01",
        )
        self.assertEqual(code, 0, stderr)
        triage = self.root / ".commit_guard" / "triage.yaml"
        self.assertTrue(triage.is_file())
        code, stdout, _ = self._run(
            "triage", "list", "--repo", str(self.root), "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(stdout)["entries"]), 1)
        code, _, _ = self._run(
            "gate", "--repo", str(self.root), "--report", str(report)
        )
        self.assertEqual(code, 0)

    def test_ingest_and_report_merge(self):
        output = self.root / "ingested.json"
        code, _, stderr = self._run(
            "ingest",
            str(FIXTURES / "semgrep.sarif"),
            "--repo",
            str(self.root),
            "--output",
            str(output),
        )
        self.assertEqual(code, 0, stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["total"], 1)
        merged = self.root / "merged.json"
        code, _, stderr = self._run(
            "report",
            "merge",
            str(output),
            str(FIXTURES / "gitleaks.json"),
            "--repo",
            str(self.root),
            "--output",
            str(merged),
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(merged.read_text(encoding="utf-8"))["total"], 2)

    def test_scan_works_without_install(self):
        (self.root / "app.py").write_text(
            'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\n',
            encoding="utf-8",
        )
        self._git("add", "app.py")
        report = self.root / "scan.json"
        code, _, stderr = self._run(
            "scan",
            str(self.root),
            "--staged",
            "--quiet",
            "--threshold",
            "info",
            "--format",
            "json",
            "--report-path",
            str(report),
            "--soft-fail",
        )
        self.assertEqual(code, 0, stderr)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertGreaterEqual(payload["total"], 1)
        self.assertEqual(payload["schema_version"], 3)

    def test_scan_gate_and_audit_profile(self):
        (self.root / "app.py").write_text(
            'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\n',
            encoding="utf-8",
        )
        self._git("add", "app.py")
        code, _stdout, stderr = self._run(
            "scan",
            str(self.root),
            "--staged",
            "--gate",
            "--quiet",
            "--threshold",
            "info",
            "--format",
            "json",
            "--report-path",
            str(self.root / "gate.json"),
        )
        self.assertEqual(code, 1, stderr)
        report = json.loads((self.root / "gate.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(report["total"], 1)
        code, _, stderr = self._run(
            "scan",
            str(self.root),
            "--staged",
            "--gate",
            "--policy-profile",
            "audit",
            "--quiet",
        )
        self.assertEqual(code, 0, stderr)

    def test_rules_list(self):
        code, _, _ = self._run("rules", "list", str(self.root))
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
