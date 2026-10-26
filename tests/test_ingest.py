from __future__ import annotations

import unittest
from pathlib import Path

from core.ingest import (
    IngestError,
    ingest_data,
    ingest_file,
    ingest_sarif,
    load_json,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ingest"


class IngestTests(unittest.TestCase):
    def test_sarif_preserves_locations_fixes_and_flows(self):
        findings = ingest_file(FIXTURES / "semgrep.sarif")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.engine, "ingest:semgrep")
        self.assertEqual(finding.category, "sast")
        self.assertEqual(finding.file, "src/db.py")
        self.assertEqual(finding.line_number, 12)
        self.assertEqual(finding.column, 5)
        self.assertEqual(finding.end_line, 12)
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertIsNotNone(finding.fix)
        self.assertEqual(len(finding.code_flows), 2)
        self.assertEqual(finding.fingerprint, "0123456789abcdef")
        self.assertEqual(finding.provenance["input_format"], "native")

    def test_sarif_suppression_is_not_blocking(self):
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "version": "2.17.0"}},
                    "results": [
                        {
                            "ruleId": "js/sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.js"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                            "suppressions": [{"kind": "inSource", "justification": "test"}],
                        }
                    ],
                }
            ],
        }
        finding = ingest_sarif(document)[0]
        self.assertFalse(finding.blocking)
        self.assertIn("suppressions", finding.provenance)

    def test_sarif_rejects_unknown_major_and_escape(self):
        with self.assertRaises(IngestError):
            ingest_sarif({"version": "3.0.0", "runs": []})
        with self.assertRaises(IngestError):
            ingest_sarif(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "Test"}},
                            "results": [
                                {
                                    "ruleId": "x",
                                    "message": {"text": "x"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "../escape.py"},
                                                "region": {"startLine": 1},
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )

    def test_semgrep_native(self):
        findings = ingest_file(FIXTURES / "semgrep.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].engine, "ingest:semgrep")
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].cwe, "CWE-95")
        self.assertEqual(findings[0].column, 5)

    def test_gitleaks_never_exposes_secret(self):
        findings = ingest_file(FIXTURES / "gitleaks.json")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.category, "secret")
        self.assertNotIn("superSecretValue", finding.flagged_code)
        self.assertNotIn("superSecretValue", finding.redacted_code)
        self.assertNotIn("superSecretValue", finding.description)
        self.assertEqual(finding.cwe, "CWE-798")

    def test_trivy_dependency_and_iac(self):
        findings = ingest_file(FIXTURES / "trivy.json")
        self.assertEqual(len(findings), 2)
        categories = {finding.category for finding in findings}
        self.assertEqual(categories, {"dependency", "iac"})
        dependency = next(item for item in findings if item.category == "dependency")
        self.assertEqual(dependency.cwe, "CWE-400")
        self.assertEqual(dependency.provenance["fixed_version"], "1.2.0")

    def test_checkov(self):
        findings = ingest_file(FIXTURES / "checkov.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "iac")
        self.assertEqual(findings[0].end_line, 14)

    def test_bandit(self):
        findings = ingest_file(FIXTURES / "bandit.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "sast")
        self.assertEqual(findings[0].cwe, "CWE-78")
        self.assertEqual(findings[0].confidence, "medium")

    def test_auto_detection(self):
        cases = {
            "semgrep.sarif": "ingest:semgrep",
            "semgrep.json": "ingest:semgrep",
            "gitleaks.json": "ingest:gitleaks",
            "trivy.json": "ingest:trivy",
            "checkov.json": "ingest:checkov",
            "bandit.json": "ingest:bandit",
        }
        for name, engine in cases.items():
            findings = ingest_data(load_json(FIXTURES / name), tool="auto")
            self.assertTrue(findings)
            self.assertTrue(all(finding.engine == engine for finding in findings), name)

    def test_unknown_tool_is_an_error(self):
        with self.assertRaises(IngestError):
            ingest_data({"mystery": []}, tool="auto")


if __name__ == "__main__":
    unittest.main()
