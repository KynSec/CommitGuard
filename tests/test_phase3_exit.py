from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import install_hook
from core.plugins import discover_plugins
from core.reporter import build_json_report
from core.scanner import Finding

FIXTURES = Path(__file__).parent / "fixtures" / "ingest"
FIVE_TOOLS = ("semgrep.sarif", "gitleaks.json", "trivy.json", "checkov.json", "grype.json")


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def finding(**overrides) -> Finding:
    payload = {
        "file": "src/commitguard.py",
        "line_number": 9,
        "rule_id": "cg-python-eval",
        "description": "eval on untrusted input",
        "severity": "high",
        "source": "ast",
        "flagged_code": "eval(value)",
        "redacted_code": "eval(value)",
        "fingerprint": "0123456789abcdef",
        "tags": ("injection",),
        "cwe": "CWE-95",
    }
    payload.update(overrides)
    return Finding(**payload)


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = install_hook.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()


class ReferenceMonorepoTests(CliTestCase):
    def test_five_tools_and_commitguard_normalize_into_one_gate(self) -> None:
        artifacts = self.root / "artifacts"
        for index, name in enumerate(FIVE_TOOLS):
            service = artifacts / f"service-{index}" / "reports"
            service.mkdir(parents=True)
            shutil.copy2(FIXTURES / name, service / name)
        write(
            self.root,
            "artifacts/commitguard/security/report.json",
            build_json_report([finding()], "high"),
        )
        write(
            self.root,
            "artifacts/history.json",
            json.dumps({"version": 1, "entries": []}),
        )

        merged = self.root / "merged.json"
        code, stdout, stderr = self.run_cli(
            "report", "merge", str(artifacts),
            "--repo", str(self.root), "--output", str(merged),
        )
        self.assertEqual(code, 0, stdout + stderr)
        payload = json.loads(merged.read_text(encoding="utf-8"))
        self.assertEqual(payload["total"], 7)
        self.assertEqual(len(payload["inputs"]), 6)
        engines = {item["engine"] for item in payload["findings"]}
        self.assertTrue(
            {"ingest:semgrep", "ingest:gitleaks", "ingest:trivy",
             "ingest:checkov", "ingest:grype"} <= engines
        )
        self.assertIn("ast", engines)

        gate_output = self.root / "gate.json"
        code, stdout, stderr = self.run_cli(
            "gate", "--repo", str(self.root), "--report", str(merged),
            "--profile", "strict", "--format", "json", "--output", str(gate_output),
        )
        self.assertEqual(code, 1, stdout + stderr)
        gate = json.loads(gate_output.read_text(encoding="utf-8"))
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["total"], 7)


class PluginLifecycleTests(CliTestCase):
    def make_plugin(self, *, signed: bool = True) -> Path:
        source = self.root / "source" / "demo"
        source.mkdir(parents=True, exist_ok=True)
        entry = source / "plugin.py"
        entry.write_text(
            "import json, sys\n"
            "json.load(sys.stdin)\n"
            "json.dump([], sys.stdout)\n",
            encoding="utf-8",
        )
        manifest = {
            "name": "demo",
            "version": "1.0.0",
            "entrypoint": "plugin.py",
            "capabilities": ["sast"],
        }
        if signed:
            manifest["signature"] = hashlib.sha256(entry.read_bytes()).hexdigest()
        (source / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
        return source

    def test_install_verify_remove_without_core_impact(self) -> None:
        source = self.make_plugin()
        plugins = self.root / "plugins"
        sbom = self.root / "sbom.json"

        code, stdout, stderr = self.run_cli(
            "plugin", "install", "--source", str(source), "--dir", str(plugins)
        )
        self.assertEqual(code, 0, stdout + stderr)
        self.assertEqual([item.name for item in discover_plugins(plugins)], ["demo"])

        code, stdout, stderr = self.run_cli(
            "plugin", "verify", "--dir", str(plugins)
        )
        self.assertEqual(code, 0, stdout + stderr)
        self.assertIn("demo: OK (signature verified)", stdout)

        code, stdout, stderr = self.run_cli(
            "sbom", str(self.root), "--format", "cyclonedx", "--output", str(sbom)
        )
        self.assertEqual(code, 0, stdout + stderr)
        self.assertEqual(json.loads(sbom.read_text())["bomFormat"], "CycloneDX")

        code, stdout, stderr = self.run_cli(
            "plugin", "remove", "--name", "demo", "--dir", str(plugins)
        )
        self.assertEqual(code, 0, stdout + stderr)
        self.assertEqual(discover_plugins(plugins), ())
        self.assertFalse((plugins / "demo").exists())

    def test_install_rejects_unsigned_and_duplicate_plugins(self) -> None:
        unsigned = self.make_plugin(signed=False)
        plugins = self.root / "plugins"
        code, _, stderr = self.run_cli(
            "plugin", "install", "--source", str(unsigned), "--dir", str(plugins)
        )
        self.assertEqual(code, 2)
        self.assertIn("unsigned", stderr)

        signed = self.make_plugin()
        code, _, stderr = self.run_cli(
            "plugin", "install", "--source", str(signed), "--dir", str(plugins)
        )
        self.assertEqual(code, 0, stderr)
        code, _, stderr = self.run_cli(
            "plugin", "install", "--source", str(signed), "--dir", str(plugins)
        )
        self.assertEqual(code, 2)
        self.assertIn("already installed", stderr)


class QuarterlyAuditTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        (self.root / "artifacts").mkdir()
        for name in FIVE_TOOLS:
            shutil.copy2(FIXTURES / name, self.root / "artifacts" / name)
        write(
            self.root,
            "commit_guard_reports/history.json",
            json.dumps(
                {
                    "version": 1,
                    "entries": [
                        {
                            "timestamp": "2026-08-15T00:00:00Z",
                            "total": 12,
                            "critical": 0,
                            "high": 4,
                            "medium": 8,
                            "low": 0,
                            "info": 0,
                            "blocked": True,
                            "threshold": "high",
                        },
                        {
                            "timestamp": "2026-11-01T00:00:00Z",
                            "total": 6,
                            "critical": 0,
                            "high": 3,
                            "medium": 3,
                            "low": 0,
                            "info": 0,
                            "blocked": True,
                            "threshold": "high",
                        },
                    ],
                }
            ),
        )
        write(
            self.root,
            ".commit_guard/triage.yaml",
            "version: 1\n"
            "entries:\n"
            "  - fingerprint: aaaaaaaaaaaaaaaa\n"
            "    state: accepted\n"
            "    owner: '@security'\n"
            "    reason: legacy finding\n"
            "    ticket: SEC-1\n"
            "    expires: '2020-01-01'\n",
        )

    def test_quarterly_audit_uses_only_local_artifacts(self) -> None:
        output = self.root / "audit.json"
        code, stdout, stderr = self.run_cli(
            "audit", str(self.root),
            "--reports", str(self.root / "artifacts"),
            "--since", "2026-10-01", "--until", "2026-11-05",
            "--pack", "owasp-top10-2021",
            "--format", "json", "--output", str(output),
        )
        self.assertEqual(code, 0, stdout + stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["period"], {"since": "2026-10-01", "until": "2026-11-05"})
        self.assertEqual(payload["total"], 6)
        self.assertEqual(len(payload["sources"]), 5)
        self.assertEqual(len(payload["history"]), 1)
        self.assertEqual(payload["triage"]["entries"], 1)
        self.assertTrue(payload["triage"]["issues"])
        self.assertIsNotNone(payload["compliance"])

    def test_strict_audit_fails_on_triage_issues(self) -> None:
        code, stdout, stderr = self.run_cli(
            "audit", str(self.root),
            "--reports", str(self.root / "artifacts"),
            "--since", "2026-10-01", "--until", "2026-11-05",
            "--strict", "--format", "json",
        )
        self.assertEqual(code, 1, stdout + stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["triage"]["issues"])
        self.assertTrue(
            any("expired" in issue for issue in payload["triage"]["issues"])
        )

    def test_strict_audit_fails_without_reports(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        code, stdout, stderr = self.run_cli(
            "audit", str(empty), "--reports", str(empty), "--strict",
            "--format", "json",
        )
        self.assertEqual(code, 1, stdout + stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["warnings"])


if __name__ == "__main__":
    unittest.main()
