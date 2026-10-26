from __future__ import annotations

import json
import unittest

from core.findings import (
    FindingSchemaError,
    canonical_path,
    extract_findings,
    finding_from_dict,
    finding_to_dict,
    infer_category,
    infer_engine,
)
from core.reporter import build_json_report, build_sarif_report
from core.scanner import Finding


def make_finding(**overrides) -> Finding:
    defaults = {
        "file": "src/app.py",
        "line_number": 7,
        "rule_id": "cg-github-token",
        "description": "A token was found.",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": 'TOKEN = "secret-value"',
        "redacted_code": 'TOKEN = "se********ue"',
        "fingerprint": "1234567890abcdef",
        "tags": ("secret", "github"),
        "cwe": "CWE-798",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class FindingSchemaTests(unittest.TestCase):
    def test_defaults_are_schema_v3_and_derived(self):
        finding = make_finding()
        self.assertEqual(finding.schema_version, 3)
        self.assertEqual(finding.engine, "regex")
        self.assertEqual(finding.category, "secret")
        self.assertEqual(finding.id, finding.fingerprint)
        self.assertEqual(finding.confidence, "medium")

    def test_ast_and_sca_inference(self):
        ast = make_finding(
            rule_id="cg-python-ast-sqli-taint",
            source="python_ast",
            tags=("sast",),
            cwe="CWE-89",
        )
        self.assertEqual(ast.engine, "ast")
        self.assertEqual(ast.category, "sast")
        self.assertEqual(ast.confidence, "high")
        sca = make_finding(
            rule_id="sca-CVE-2024-0001",
            source="sca",
            tags=("dependency",),
            cwe=None,
            fixed_versions=("1.2.0",),
        )
        self.assertEqual(sca.category, "dependency")

    def test_infer_category_and_engine_helpers(self):
        self.assertEqual(
            infer_category(rule_id="x", source="checkov", tags=("iac",)),
            "iac",
        )
        self.assertEqual(
            infer_engine("ingest:semgrep", "x"), "ingest:semgrep"
        )
        self.assertEqual(infer_engine("sca", "x"), "sca")

    def test_roundtrip_preserves_v3_fields_and_unknowns(self):
        finding = make_finding(
            engine="ast",
            category="sast",
            confidence="high",
            column=3,
            end_line=8,
            end_column=10,
            fix={"description": "fix", "edits": []},
            references=("https://example.invalid/a",),
            code_flows=({"file": "src/app.py", "line": 1},),
            also_reported_by=("semgrep",),
            rule_version="1",
            pack_version="core/1",
            provenance={"tool": "test"},
        )
        payload = finding_to_dict(finding)
        payload["future_field"] = {"kept": True}
        restored = finding_from_dict(payload)
        self.assertEqual(restored.engine, "ast")
        self.assertEqual(restored.category, "sast")
        self.assertEqual(restored.column, 3)
        self.assertEqual(restored.end_line, 8)
        self.assertEqual(restored.fix, finding.fix)
        self.assertEqual(restored.code_flows, finding.code_flows)
        self.assertEqual(restored.also_reported_by, ("semgrep",))
        self.assertEqual(
            restored.provenance["unknown"]["future_field"], {"kept": True}
        )

    def test_extract_rejects_future_schema(self):
        with self.assertRaises(FindingSchemaError):
            extract_findings({"schema_version": 99, "findings": []})

    def test_canonical_path_rejects_escape(self):
        with self.assertRaises(FindingSchemaError):
            canonical_path("../secret.txt")
        with self.assertRaises(FindingSchemaError):
            canonical_path("/etc/passwd")
        self.assertEqual(canonical_path("./src\\app.py"), "src/app.py")

    def test_json_report_uses_v3_fields(self):
        payload = json.loads(build_json_report([make_finding()], "high"))
        self.assertEqual(payload["schema_version"], 3)
        item = payload["findings"][0]
        for key in ("id", "engine", "category", "confidence", "references", "code_flows", "provenance"):
            self.assertIn(key, item)
        self.assertEqual(item["engine"], "regex")
        self.assertEqual(item["category"], "secret")

    def test_sarif_contains_v3_metadata_and_flows(self):
        finding = make_finding(
            engine="ast",
            category="sast",
            confidence="high",
            column=2,
            end_line=7,
            fix={"description": "fix", "edits": [{"start_line": 7, "end_line": 7, "replacement": "safe"}]},
            code_flows=({"file": "src/app.py", "line": 1, "message": "source"},),
        )
        payload = json.loads(build_sarif_report([finding], "high"))
        result = payload["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["engine"], "ast")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startColumn"], 2)
        self.assertIn("fixes", result)
        self.assertIn("codeFlows", result)
        self.assertEqual(
            payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["category"],
            "sast",
        )


if __name__ == "__main__":
    unittest.main()
