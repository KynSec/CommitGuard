# SPDX-License-Identifier: Apache-2.0
"""Tests for the Phase 2/3 developer, supply-chain, and plugin surfaces."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import install_hook
from core.compliance import (
    CompliancePack,
    Control,
    discover_packs,
    evaluate_compliance,
    format_compliance_report,
)
from core.dashboard import build_dashboard_data, render_dashboard
from core.ingest import ingest_data
from core.license_policy import (
    classify_license,
    evaluate_licenses,
    load_license_policy,
    normalize_license,
)
from core.lsp import LanguageServer, read_message, write_message
from core.plugins import discover_plugins, load_manifest, run_plugin
from core.report_merge import merge_reports
from core.reporter import build_json_report
from core.sbom import build_sbom, collect_licenses
from core.scanner import Finding
from core.watch import diff_snapshots, run_watch


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def finding(**overrides) -> Finding:
    payload = {
        "file": "src/app.py",
        "line_number": 4,
        "rule_id": "cg-python-eval",
        "description": "eval on untrusted input",
        "severity": "high",
        "source": "ast",
        "flagged_code": "eval(value)",
        "redacted_code": "eval(value)",
        "fingerprint": "abcdef0123456789",
        "tags": ("injection",),
        "cwe": "CWE-95",
    }
    payload.update(overrides)
    return Finding(**payload)


class SupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        write(
            self.root,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "demo"},
                        "node_modules/good": {"version": "1.0.0", "license": "MIT"},
                        "node_modules/bad": {"version": "2.0.0", "license": "AGPL-3.0-only"},
                        "node_modules/unknown": {"version": "3.0.0"},
                    },
                }
            ),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_licenses_and_sbom_formats(self) -> None:
        licenses = collect_licenses(self.root)
        self.assertEqual(len(licenses), 3)
        cyclonedx = build_sbom(self.root, fmt="cyclonedx", project_name="Demo")
        self.assertEqual(cyclonedx["specVersion"], "1.6")
        names = {item["name"] for item in cyclonedx["components"]}
        self.assertEqual(names, {"good", "bad", "unknown"})
        spdx = build_sbom(self.root, fmt="spdx", project_name="Demo")
        declared = {item["name"]: item["licenseDeclared"] for item in spdx["packages"]}
        self.assertEqual(declared["good"], "MIT")
        self.assertEqual(declared["unknown"], "NOASSERTION")

    def test_license_policy_fails_on_denied_and_strict_unknown(self) -> None:
        report = evaluate_licenses(self.root, policy=load_license_policy(self.root))
        self.assertTrue(report.failed)
        self.assertEqual(report.counts["denied"], 1)
        self.assertEqual(report.counts["unknown"], 1)
        strict = load_license_policy(self.root, fail_on_unknown=True)
        self.assertTrue(evaluate_licenses(self.root, policy=strict).failed)

    def test_license_expressions_and_alias_normalization(self) -> None:
        policy = load_license_policy(self.root)
        self.assertEqual(classify_license("MIT OR GPL-3.0-only", policy), "allowed")
        self.assertEqual(classify_license("GPL-3.0-only AND MIT", policy), "denied")
        self.assertEqual(
            classify_license("GPL-3.0-only OR AGPL-3.0-only", policy), "denied"
        )
        self.assertEqual(normalize_license("mit"), "MIT")
        self.assertEqual(normalize_license("GPL-3.0"), "GPL-3.0-only")
        normalized = load_license_policy(self.root, allow=("mit license",))
        self.assertIn("MIT", normalized.allow)

    def test_legacy_nested_package_lock_licenses(self) -> None:
        legacy = Path(self.temp.name) / "legacy"
        write(
            legacy,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "parent": {
                            "version": "1.0.0",
                            "license": "MIT",
                            "dependencies": {
                                "child": {
                                    "version": "2.0.0",
                                    "license": "Apache-2.0",
                                    "dependencies": {
                                        "grandchild": {
                                            "version": "3.0.0",
                                            "license": "BSD-3-Clause",
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ),
        )
        declared = {item.name: item.license for item in collect_licenses(legacy)}
        self.assertEqual(
            declared,
            {"parent": "MIT", "child": "Apache-2.0", "grandchild": "BSD-3-Clause"},
        )

    def test_grype_ingestion(self) -> None:
        document = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-0001",
                        "severity": "High",
                        "description": "demo vulnerability",
                        "fix": {"versions": ["2.0.0"]},
                        "cwes": [{"cwe": "CWE-79", "source": "nvd"}],
                    },
                    "artifact": {
                        "name": "demo-package",
                        "version": "1.0.0",
                        "type": "npm",
                        "locations": [{"path": "package-lock.json"}],
                    },
                }
            ]
        }
        findings = ingest_data(document, tool="auto", repo_root=self.root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "dependency")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].cwe, "CWE-79")


class DeveloperSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        write(
            self.root,
            "rules/custom_rules.yaml",
            'rules:\n  - id: cg-eval\n    description: eval\n    severity: high\n'
            '    pattern: "eval\\\\("\n',
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_watch_snapshot_diff_and_once(self) -> None:
        write(self.root, "app.py", "print('one')\n")
        previous = {"app.py": (1, 1), "old.py": (1, 1)}
        current = {"app.py": (2, 1), "new.py": (1, 1)}
        event = diff_snapshots(previous, current)
        self.assertEqual(event.changed, ("app.py",))
        self.assertEqual(event.added, ("new.py",))
        self.assertEqual(event.removed, ("old.py",))
        calls = []
        state = run_watch(self.root, lambda event: calls.append(event), once=True)
        self.assertEqual(state.scans, 1)
        self.assertEqual(len(calls), 1)

    def test_lsp_initialize_and_diagnostics(self) -> None:
        stdin = io.BytesIO()
        stdout = io.BytesIO()
        uri = (self.root / "app.py").as_uri()
        write_message(stdin, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        write_message(
            stdin,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "text": 'result = eval("1")\n',
                        "version": 1,
                    }
                },
            },
        )
        write_message(stdin, {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}})
        write_message(stdin, {"jsonrpc": "2.0", "method": "exit", "params": {}})
        stdin.seek(0)
        code = LanguageServer(self.root).serve(stdin, stdout)
        self.assertEqual(code, 0)
        stdout.seek(0)
        messages = []
        while True:
            message = read_message(stdout)
            if message is None:
                break
            messages.append(message)
        self.assertEqual(messages[0]["result"]["serverInfo"]["name"], "commitguard-lsp")
        diagnostics = next(
            item
            for item in messages
            if item.get("method") == "textDocument/publishDiagnostics"
        )["params"]["diagnostics"]
        self.assertEqual(diagnostics[0]["code"], "cg-eval")

    def test_lsp_save_with_empty_text_clears_diagnostics(self) -> None:
        uri = (self.root / "app.py").as_uri()
        server = LanguageServer(self.root)
        stdout = io.BytesIO()
        server.handle(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "text": 'result = eval("1")\n',
                        "version": 1,
                    }
                },
            },
            stdout,
        )
        self.assertTrue(server.diagnostics[uri])
        stdout = io.BytesIO()
        server.handle(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didSave",
                "params": {"textDocument": {"uri": uri}, "text": ""},
            },
            stdout,
        )
        self.assertEqual(server.diagnostics[uri], [])

    def test_dashboard_and_compliance(self) -> None:
        report = self.root / "commit_guard_reports" / "report.json"
        write(self.root, "commit_guard_reports/report.json", build_json_report([finding()], "high"))
        write(
            self.root,
            "commit_guard_reports/history.json",
            json.dumps({"version": 1, "entries": []}),
        )
        data = build_dashboard_data(self.root)
        self.assertEqual(len(data.findings), 1)
        self.assertEqual(data.warnings, ())
        self.assertIn("src/app.py", render_dashboard(data))
        packs = discover_packs(names=["owasp-top10-2021"])
        compliance = evaluate_compliance(list(data.findings), packs)
        self.assertEqual(compliance.coverage[0].control_id, "A03:2021")
        self.assertIn("Mapping is not certification", format_compliance_report(compliance))
        self.assertTrue(report.is_file())

        custom = CompliancePack(
            id="custom",
            name="Custom",
            version="1",
            controls=(
                Control(
                    id="C-1",
                    title="Injection",
                    categories=("Injection",),
                ),
            ),
        )
        matched = evaluate_compliance(
            [finding(category="injection")], [custom]
        )
        self.assertEqual(matched.coverage[0].control_id, "C-1")

    def test_report_merge_expands_directories(self) -> None:
        first = self.root / "artifacts" / "one" / "report.json"
        second = self.root / "artifacts" / "two" / "report.json"
        write(self.root, "artifacts/one/report.json", build_json_report([finding()], "high"))
        write(
            self.root,
            "artifacts/two/report.json",
            build_json_report([finding(file="src/other.py", fingerprint="1234567890abcdef")], "high"),
        )
        write(
            self.root,
            "artifacts/history.json",
            json.dumps({"version": 1, "entries": []}),
        )
        merged = merge_reports([self.root / "artifacts"], repo_root=self.root)
        self.assertEqual(len(merged.findings), 2)
        self.assertEqual(len(merged.sources), 2)
        self.assertTrue(first.is_file() and second.is_file())


class PluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plugin_dir = self.root / "plugins" / "demo"
        self.plugin_dir.mkdir(parents=True)
        self.entry = self.plugin_dir / "plugin.py"
        self.entry.write_text(
            "import json, sys\n"
            "request = json.load(sys.stdin)\n"
            "finding = {\n"
            "  'file': 'app.js', 'line': 1, 'rule_id': 'plugin-test',\n"
            "  'severity': 'medium', 'description': 'plugin finding',\n"
            "  'category': 'sast', 'confidence': 'high',\n"
            "}\n"
            "json.dump([finding], sys.stdout)\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(self.entry.read_bytes()).hexdigest()
        (self.plugin_dir / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "entrypoint": "plugin.py",
                    "capabilities": ["sast"],
                    "signature": digest,
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_signed_plugin_runs_out_of_process(self) -> None:
        manifest = load_manifest(self.plugin_dir / "plugin.json")
        result = run_plugin(manifest, context={"repo_root": str(self.root)})
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.findings[0].engine, "plugin:demo")

    def test_unsigned_plugin_requires_explicit_flag(self) -> None:
        manifest_path = self.plugin_dir / "plugin.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload.pop("signature")
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        manifest = load_manifest(manifest_path)
        result = run_plugin(manifest)
        self.assertFalse(result.ok)
        self.assertIn("unsigned", result.errors[0])
        allowed = run_plugin(manifest, allow_unsigned=True)
        self.assertTrue(allowed.ok, allowed.errors)

    def test_discover_plugins_accepts_the_plugin_directory_itself(self) -> None:
        manifests = discover_plugins(self.plugin_dir)
        self.assertEqual([manifest.name for manifest in manifests], ["demo"])
        parent = discover_plugins(self.plugin_dir.parent)
        self.assertEqual([manifest.name for manifest in parent], ["demo"])


class CliSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        import subprocess

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        write(self.root, "package-lock.json", json.dumps({"packages": {"node_modules/demo": {"version": "1.0.0", "license": "MIT"}}}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = install_hook.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_sbom_license_dashboard_and_watch_smoke(self) -> None:
        output = self.root / "sbom.json"
        code, _, _ = self._run("sbom", str(self.root), "--format", "cyclonedx", "--output", str(output))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text())["bomFormat"], "CycloneDX")
        code, stdout, _ = self._run("license", str(self.root), "--format", "json")
        self.assertEqual(code, 0, stdout)
        code, _, _ = self._run("dashboard", str(self.root), "--format", "json")
        self.assertEqual(code, 0)
        code, _, _ = self._run("watch", str(self.root), "--once", "--all", "--quiet")
        self.assertEqual(code, 0)

    def test_license_strict_fails_on_unknown_licenses(self) -> None:
        write(
            self.root,
            "package-lock.json",
            json.dumps(
                {"packages": {"node_modules/unknown": {"version": "3.0.0"}}}
            ),
        )
        code, stdout, _ = self._run("license", str(self.root), "--strict", "--format", "json")
        self.assertEqual(code, 1, stdout)
        payload = json.loads(stdout)
        self.assertTrue(payload["failed"])
        self.assertTrue(payload["policy"]["fail_on_unknown"])
        self.assertTrue(payload["policy"]["fail_on_review"])

    def test_plugin_validate_accepts_the_plugin_directory_itself(self) -> None:
        plugin_dir = self.root / "plugins" / "demo"
        entry = plugin_dir / "plugin.py"
        write(self.root, "plugins/demo/plugin.py", "print('[]')\n")
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        write(
            self.root,
            "plugins/demo/plugin.json",
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "entrypoint": "plugin.py",
                    "capabilities": ["sast"],
                    "signature": digest,
                }
            ),
        )
        code, stdout, _ = self._run(
            "plugin", "validate", "--dir", str(plugin_dir)
        )
        self.assertEqual(code, 0, stdout)
        self.assertIn("demo: OK", stdout)


if __name__ == "__main__":
    unittest.main()


class JavaScriptTaintTests(unittest.TestCase):
    def test_javascript_source_to_sink_flow(self) -> None:
        from core.ast_taint import scan_js_taint

        files = {
            "app.ts": [
                "const userId = req.query.id;",
                'const query = "SELECT * FROM users WHERE id=" + userId;',
                "pool.query(query);",
            ]
        }
        result = scan_js_taint(files, {"app.ts": {1, 2, 3}})
        self.assertEqual(len(result.matches), 1)
        finding = result.matches[0].finding
        self.assertEqual(finding.rule_id, "cg-js-ast-sqli-taint")
        self.assertEqual(finding.source, "javascript_ast")

    def test_javascript_taint_requires_changed_source_or_sink(self) -> None:
        from core.ast_taint import scan_js_taint

        files = {"app.js": ["const id = req.query.id;", "eval(id);"]}
        result = scan_js_taint(files, {"app.js": {2}})
        self.assertEqual(result.matches[0].finding.rule_id, "cg-js-ast-code-exec-taint")
        self.assertEqual(scan_js_taint(files, {"app.js": set()}).matches, ())
