from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.report_merge import MergeError, load_report, merge_reports, write_merged_json
from core.reporter import build_json_report
from core.scanner import Finding

FIXTURES = Path(__file__).parent / "fixtures" / "ingest"


def finding(**overrides) -> Finding:
    payload = {
        "file": "src/app.py",
        "line_number": 7,
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


class ReportMergeTests(unittest.TestCase):
    def test_load_commitguard_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(build_json_report([finding()], "high"), encoding="utf-8")
            findings, source = load_report(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(source.format, "commitguard-json")
        self.assertEqual(source.finding_count, 1)
        self.assertEqual(len(source.digest), 16)
        self.assertEqual(source.tool_versions["CommitGuard"], "2.1.0")

    def test_merge_deduplicates_same_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a.json"
            second = Path(directory) / "b.json"
            text = build_json_report([finding()], "high")
            first.write_text(text, encoding="utf-8")
            second.write_text(text, encoding="utf-8")
            merged = merge_reports([first, second])
            output = Path(directory) / "merged.json"
            write_merged_json(merged, output)
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(len(merged.findings), 1)
        self.assertEqual(len(merged.sources), 2)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(len(payload["inputs"]), 2)
        self.assertEqual(payload["schema_version"], 3)

    def test_merge_json_and_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            json_report = Path(directory) / "report.json"
            json_report.write_text(build_json_report([finding()], "high"), encoding="utf-8")
            merged = merge_reports([json_report, FIXTURES / "semgrep.sarif"])
        self.assertEqual(len(merged.findings), 2)
        self.assertEqual(len(merged.sources), 2)
        self.assertIn("Semgrep", merged.tool_versions)

    def test_invalid_json_raises_merge_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(MergeError):
                merge_reports([path])


if __name__ == "__main__":
    unittest.main()
