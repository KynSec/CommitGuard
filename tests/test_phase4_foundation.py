from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import install_hook
from core.ai_assistant import (
    AIError,
    build_context_package,
    context_from_finding,
    resolve_provider,
)
from core.reachability import (
    annotate_reachability,
    assess_package,
    import_names_for,
)
from core.reporter import build_json_report
from core.scanner import Finding
from core.vex import (
    VEXError,
    apply_vex,
    export_openvex,
    parse_vex,
)
from main import run_scan

GIT = shutil.which("git")
VULN = {
    "id": "GHSA-requests-test",
    "aliases": ["CVE-2024-0001"],
    "summary": "Requests test vulnerability.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
            ],
        }
    ],
}


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sca_finding(**overrides) -> Finding:
    payload = {
        "file": "requirements.txt",
        "line_number": 1,
        "rule_id": "sca-GHSA-requests-test",
        "description": "Vulnerable dependency requests 2.19.0.",
        "severity": "high",
        "source": "sca",
        "flagged_code": "requests==2.19.0",
        "redacted_code": "requests==2.19.0",
        "fingerprint": "sca0123456789ab",
        "tags": ("sca", "dependency", "pypi"),
        "cwe": "CWE-1104",
        "fixed_versions": ("2.32.0",),
        "aliases": ("CVE-2024-0001",),
        "advisory_url": "https://github.com/advisories/GHSA-requests-test",
    }
    payload.update(overrides)
    return Finding(**payload)


class VEXTests(unittest.TestCase):
    def test_openvex_not_affected_marks_finding_non_blocking(self) -> None:
        document = parse_vex(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "author": "Security",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2024-0001"},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            }
        )
        application = apply_vex([sca_finding()], document)
        self.assertEqual(application.suppressed, 1)
        self.assertEqual(len(application.findings), 1)
        finding = application.findings[0]
        self.assertFalse(finding.blocking)
        self.assertEqual(finding.provenance["vex"]["status"], "not_affected")

    def test_affected_statement_keeps_finding_blocking(self) -> None:
        document = parse_vex(
            {
                "statements": [
                    {"vulnerability": "GHSA-requests-test", "status": "affected"}
                ]
            }
        )
        application = apply_vex([sca_finding()], document)
        self.assertEqual(application.suppressed, 0)
        self.assertTrue(application.findings[0].blocking)
        self.assertEqual(application.annotated, 1)

    def test_cyclonedx_false_positive_maps_to_not_affected(self) -> None:
        document = parse_vex(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-0001",
                        "analysis": {
                            "state": "false_positive",
                            "justification": "code_not_reachable",
                        },
                        "affects": [{"ref": "pkg:pypi/requests@2.19.0"}],
                    }
                ],
            }
        )
        self.assertEqual(document.fmt, "cyclonedx")
        self.assertEqual(document.statements[0].status, "not_affected")
        application = apply_vex([sca_finding()], document)
        self.assertFalse(application.findings[0].blocking)

    def test_export_openvex_round_trips(self) -> None:
        document = export_openvex([sca_finding()], author="Tester")
        self.assertEqual(len(document.statements), 1)
        payload = document.to_openvex()
        self.assertEqual(payload["author"], "Tester")
        self.assertEqual(payload["statements"][0]["status"], "affected")
        parsed = parse_vex(json.loads(json.dumps(payload)))
        self.assertEqual(parsed.statements[0].vulnerability, "GHSA-requests-test")

    def test_invalid_document_raises(self) -> None:
        with self.assertRaises(VEXError):
            parse_vex({"not": "vex"})
        with self.assertRaises(VEXError):
            parse_vex({"statements": [{"vulnerability": "X", "status": "bogus"}]})


class ReachabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_import_names_use_known_aliases(self) -> None:
        self.assertEqual(import_names_for("PyYAML", "PyPI"), ("yaml", "pyyaml"))
        self.assertEqual(import_names_for("beautifulsoup4", "PyPI"), ("bs4", "beautifulsoup4"))

    def test_reachable_package_is_detected(self) -> None:
        write(self.root, "app.py", "import requests\n\nrequests.get('https://example.com')\n")
        result = assess_package(self.root, "requests", "PyPI")
        self.assertTrue(result.reachable)
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.evidence, ("app.py",))

    def test_unreachable_package_is_reported_as_evidence_gap(self) -> None:
        write(self.root, "app.py", "import json\n")
        result = assess_package(self.root, "requests", "PyPI")
        self.assertFalse(result.reachable)
        self.assertEqual(result.confidence, "low")

    def test_annotate_reachability_preserves_finding(self) -> None:
        write(self.root, "app.py", "import requests\n")
        assessment = assess_package(self.root, "requests", "PyPI")
        findings = annotate_reachability(
            [sca_finding()], {"GHSA-requests-test": assessment}
        )
        self.assertTrue(findings[0].blocking)
        self.assertTrue(findings[0].provenance["reachability"]["reachable"])


class AIAssistantTests(unittest.TestCase):
    def test_context_package_redacts_secret_values(self) -> None:
        finding = Finding(
            file="settings.py",
            line_number=3,
            rule_id="gitleaks-generic-api-key",
            description="Hardcoded API key",
            severity="high",
            source="regex",
            flagged_code='api_key = "SUPER_SECRET_VALUE"',  # commit-guard-ignore
            redacted_code='api_key = "SU**********UE"',
            fingerprint="secret123456789",
            tags=("secret",),
            category="secret",
        )
        package = build_context_package("/repo", [finding])
        text = package.to_markdown()
        self.assertNotIn("SUPER_SECRET_VALUE", text)
        self.assertIn("SU**********UE", text)
        self.assertIn("Rotate the exposed credential", text)

    def test_context_package_truncates_to_budget(self) -> None:
        findings = [
            Finding(
                file=f"file{i}.py",
                line_number=1,
                rule_id=f"rule-{i}",
                description="x" * 500,
                severity="high",
                source="ast",
                flagged_code="code" * 50,
                fingerprint=f"fp{i}",
            )
            for i in range(5)
        ]
        package = build_context_package("/repo", findings, max_chars=600)
        self.assertTrue(package.truncated)
        self.assertLess(len(package.findings), 5)

    def test_remote_provider_requires_explicit_opt_in(self) -> None:
        with self.assertRaises(AIError):
            resolve_provider("openai-compatible")
        self.assertEqual(resolve_provider("local").name, "local")

    def test_remediation_prefers_fixed_versions(self) -> None:
        context = context_from_finding(sca_finding())
        self.assertIn("2.32.0", context.remediation)


class Phase4CliTests(unittest.TestCase):
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

    def _report(self) -> Path:
        path = self.root / "report.json"
        path.write_text(build_json_report([sca_finding()], "high"), encoding="utf-8")
        return path

    def test_vex_export_and_apply(self) -> None:
        report = self._report()
        vex_path = self.root / "vex.json"
        code, _out, _err = self.run_cli(
            "vex", "export", "--report", str(report), "--output", str(vex_path)
        )
        self.assertEqual(code, 0)
        self.assertTrue(vex_path.is_file())
        exported = json.loads(vex_path.read_text())
        self.assertEqual(exported["statements"][0]["status"], "affected")

        document = json.loads(vex_path.read_text())
        document["statements"][0]["status"] = "not_affected"
        vex_path.write_text(json.dumps(document), encoding="utf-8")
        output = self.root / "filtered.json"
        code, _out, _err = self.run_cli(
            "vex", "apply", "--report", str(report), "--vex", str(vex_path),
            "--output", str(output),
        )
        self.assertEqual(code, 0)
        filtered = json.loads(output.read_text())
        self.assertFalse(filtered["findings"][0]["blocking"])
        self.assertEqual(filtered["vex"]["suppressed"], 1)

    def test_ai_context_and_explain(self) -> None:
        report = self._report()
        context_path = self.root / "context.json"
        code, _out, _err = self.run_cli(
            "ai", "context", "--report", str(report), "--format", "json",
            "--output", str(context_path),
        )
        self.assertEqual(code, 0)
        context = json.loads(context_path.read_text())
        self.assertEqual(context["provider"], "local")
        self.assertEqual(len(context["findings"]), 1)

        code, stdout, _err = self.run_cli(
            "ai", "explain", "--report", str(report)
        )
        self.assertEqual(code, 0)
        self.assertIn("sca-GHSA-requests-test", stdout)
        self.assertIn("2.32.0", stdout)


@unittest.skipUnless(GIT, "git is required for integration tests")
class Phase4ScanIntegrationTests(unittest.TestCase):
    def test_vex_and_reachability_flow_through_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            write(root, "requirements.txt", "requests==2.19.0\n")
            write(root, ".commit_guard_osv.json", json.dumps({"vulnerabilities": [VULN]}))
            write(root, "app.py", "import requests\n")
            write(
                root,
                "vex.json",
                json.dumps(
                    {
                        "statements": [
                            {
                                "vulnerability": "CVE-2024-0001",
                                "status": "not_affected",
                                "justification": "vulnerable_code_not_in_execute_path",
                            }
                        ]
                    }
                ),
            )
            exit_code = run_scan(
                repo_dir=root,
                quiet=True,
                use_baseline=False,
                sca=True,
                sca_reachability=True,
                vex_path=root / "vex.json",
                fmt="json",
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(
                (root / "commit_guard_reports/report.json").read_text()
            )
            finding = payload["findings"][0]
            self.assertFalse(finding["blocking"])
            self.assertEqual(finding["provenance"]["vex"]["status"], "not_affected")
            self.assertTrue(finding["provenance"]["reachability"]["reachable"])


if __name__ == "__main__":
    unittest.main()
