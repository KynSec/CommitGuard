from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks import ai_evaluation, leaderboard
from core.commands import command_packs
from core.engines import ScanContext, TaintEngine
from core.git_diff import DiffLine
from core.interprocedural import scan_interprocedural
from core.rule_packs import (
    RulePackError,
    install_from_registry,
    install_pack,
    load_pack,
    load_registry,
    pack_digest,
    sign_pack,
    validate_pack_rules,
    verify_pack,
)
from core.scan_profiles import ast_rule_source
from scripts.build_native import build_command

JS_FILES = {
    "api.js": [
        "function fetchUser(req) {",
        "  return req.query.id;",
        "}",
        "module.exports = { fetchUser };",
    ],
    "app.js": [
        "const { fetchUser } = require('./api');",
        "function view(req, db) {",
        "  const id = fetchUser(req);",
        "  db.query('SELECT * FROM users WHERE id=' + id);",
        "}",
    ],
}

JAVA_FILES = {
    "Flow.java": [
        "class Flow {",
        "  String value(HttpServletRequest request) {",
        "    return request.getParameter(\"cmd\");",
        "  }",
        "  void run(HttpServletRequest request) {",
        "    String cmd = value(request);",
        "    Runtime.getRuntime().exec(cmd);",
        "  }",
        "}",
    ]
}

GO_FILES = {
    "flow.go": [
        "package main",
        "func value(r *http.Request) string {",
        "  return r.FormValue(\"cmd\")",
        "}",
        "func run(r *http.Request) {",
        "  cmd := value(r)",
        "  exec.Command(\"sh\", \"-c\", cmd)",
        "}",
    ],
}


class InterproceduralTests(unittest.TestCase):
    def _changed(self, files: dict[str, list[str]]) -> dict[str, set[int]]:
        return {path: set(range(1, len(lines) + 1)) for path, lines in files.items()}

    def test_javascript_cross_file_flow(self) -> None:
        result = scan_interprocedural(JS_FILES, self._changed(JS_FILES))
        self.assertEqual(
            [match.finding.rule_id for match in result.matches],
            ["cg-js-ast-sqli-taint"],
        )
        self.assertEqual(result.matches[0].finding.file, "app.js")

    def test_javascript_fixed_flow_is_clean(self) -> None:
        files = {
            "api.js": JS_FILES["api.js"],
            "app.js": [
                "const { fetchUser } = require('./api');",
                "function view(req, db) {",
                "  fetchUser(req);",
                "  db.query('SELECT * FROM users WHERE id = 42');",
                "}",
            ],
        }
        result = scan_interprocedural(files, self._changed(files))
        self.assertEqual(result.matches, ())

    def test_java_interprocedural_flow(self) -> None:
        result = scan_interprocedural(JAVA_FILES, self._changed(JAVA_FILES))
        self.assertEqual(
            [match.finding.rule_id for match in result.matches],
            ["cg-java-ast-code-exec-taint"],
        )

    def test_go_interprocedural_flow(self) -> None:
        result = scan_interprocedural(GO_FILES, self._changed(GO_FILES))
        self.assertEqual(
            [match.finding.rule_id for match in result.matches],
            ["cg-go-ast-code-exec-taint"],
        )

    def test_rule_sources_for_new_languages(self) -> None:
        self.assertEqual(ast_rule_source("cg-java-ast-sqli-taint"), "java_ast")
        self.assertEqual(ast_rule_source("cg-go-ast-sqli-taint"), "go_ast")
        self.assertEqual(ast_rule_source("cg-js-ast-sqli-taint"), "javascript_ast")
        self.assertEqual(ast_rule_source("cg-python-ast-sqli-taint"), "python_ast")

    def test_missing_file_content_warns(self) -> None:
        result = scan_interprocedural({}, {"app.js": {1}})
        self.assertTrue(result.warnings)

    def test_taint_engine_merges_interprocedural_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, lines in JS_FILES.items():
                (root / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
            app_lines = JS_FILES["app.js"]
            context = ScanContext(
                repo_root=root,
                diff_lines=(
                    DiffLine("app.js", 4, app_lines[3]),
                ),
                changed_paths=("app.js",),
                files={"app.js": app_lines},
                file_lines={"app.js": app_lines},
            )
            result = TaintEngine().run(context)
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            ["cg-js-ast-sqli-taint"],
        )


class RulePackTests(unittest.TestCase):
    def _make_pack(self, root: Path, *, name: str = "acme") -> Path:
        pack_dir = root / "source" / name
        pack_dir.mkdir(parents=True)
        (pack_dir / "pack.yaml").write_text(
            "name: acme\n"
            "version: 1.0.0\n"
            "description: test pack\n"
            "license: Apache-2.0\n"
            "source: https://example.invalid/acme\n"
            "rules: rules.yaml\n",
            encoding="utf-8",
        )
        (pack_dir / "rules.yaml").write_text(
            "rules:\n"
            "  - id: acme-secret\n"
            "    description: test\n"
            '    regex: "ACME_SECRET_[A-Z]+"\n'
            "    severity: high\n"
            "    tags: [secret]\n",
            encoding="utf-8",
        )
        return pack_dir

    def test_sign_and_verify_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pack_dir = self._make_pack(Path(directory))
            pack = load_pack(pack_dir)
            sign_pack(pack, "test-key")
            signed = load_pack(pack_dir)
            ok, reason = verify_pack(signed, "test-key", required=True)
            rule_count = validate_pack_rules(signed)[0]
        self.assertTrue(ok, reason)
        self.assertEqual(rule_count, 1)

    def test_tampered_pack_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pack_dir = self._make_pack(Path(directory))
            pack = load_pack(pack_dir)
            sign_pack(pack, "test-key")
            (pack_dir / "rules.yaml").write_text(
                "rules:\n  - id: evil\n    regex: evil\n    severity: high\n",
                encoding="utf-8",
            )
            tampered = load_pack(pack_dir)
            ok, _reason = verify_pack(tampered, "test-key", required=True)
        self.assertFalse(ok)

    def test_install_requires_signature_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack_dir = self._make_pack(root)
            with self.assertRaises(RulePackError):
                install_pack(pack_dir, directory=root / "installed", key="test-key")

    def test_install_and_registry_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack_dir = self._make_pack(root)
            sign_pack(load_pack(pack_dir), "test-key")
            installed = install_pack(
                pack_dir,
                directory=root / "installed",
                key="test-key",
            )
            self.assertEqual(installed.name, "acme")
            registry = root / "registry"
            registry.mkdir()
            (registry / "registry.json").write_text(
                json.dumps(
                    {
                        "packs": [
                            {
                                "name": "acme",
                                "version": "1.0.0",
                                "source": str(pack_dir),
                                "digest": pack_digest(load_pack(pack_dir)),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(len(load_registry(registry).entries), 1)
            from_registry = install_from_registry(
                registry,
                "acme",
                directory=root / "from-registry",
                key="test-key",
            )
        self.assertEqual(from_registry.name, "acme")

    def test_registry_digest_mismatch_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack_dir = self._make_pack(root)
            sign_pack(load_pack(pack_dir), "test-key")
            registry = root / "registry"
            registry.mkdir()
            (registry / "registry.json").write_text(
                json.dumps(
                    {
                        "packs": [
                            {
                                "name": "acme",
                                "version": "1.0.0",
                                "source": str(pack_dir),
                                "digest": "0" * 64,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(RulePackError):
                install_from_registry(
                    registry,
                    "acme",
                    directory=root / "from-registry",
                    key="test-key",
                )
            self.assertFalse((root / "from-registry" / "acme").exists())

    def test_command_packs_json_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack_dir = self._make_pack(root)
            sign_pack(load_pack(pack_dir), "test-key")
            install_pack(
                pack_dir, directory=root / "installed", key="test-key"
            )
            output = root / "packs.json"
            code = command_packs(
                "list",
                directory=root / "installed",
                fmt="json",
                output=output,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(payload["packs"][0]["name"], "acme")

    def test_command_packs_sign_with_env_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack_dir = self._make_pack(root)
            with patch.dict(os.environ, {"COMMIT_GUARD_RULE_PACK_KEY": "env-key"}):
                code = command_packs("sign", directory=root / "source")
            self.assertEqual(code, 0)
            ok, _reason = verify_pack(load_pack(pack_dir), "env-key", required=True)
        self.assertTrue(ok)


class BenchmarkArtifactTests(unittest.TestCase):
    def test_ai_evaluation_suite_passes(self) -> None:
        payload = ai_evaluation.run()
        self.assertTrue(payload["suite_passed"])
        self.assertGreaterEqual(int(payload["checks"]), 20)

    def test_leaderboard_collects_and_renders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "accuracy.json").write_text(
                json.dumps(
                    {
                        "suite": "accuracy",
                        "cases": 2,
                        "checks": 4,
                        "passed": 4,
                        "failed": 0,
                    }
                ),
                encoding="utf-8",
            )
            (root / "scan.json").write_text(
                json.dumps({"median_ms": 120.0, "findings": 0}),
                encoding="utf-8",
            )
            rows = leaderboard.collect([root], version="3.0.0")
            markdown = leaderboard.render_markdown(
                rows, metadata={"commit": "abc", "python": "3.13"}
            )
        self.assertEqual(len(rows), 2)
        self.assertIn("accuracy", markdown)
        self.assertIn("scan-benchmark", markdown)

    def test_native_build_command_has_entrypoint_and_data(self) -> None:
        command = build_command(
            Path("/tmp/out"), name="commit-guard", onefile=True, console=True, clean=True
        )
        self.assertIn("--onefile", command)
        self.assertIn(str(Path(__file__).resolve().parent.parent / "main.py"), command)
        self.assertTrue(any(item.startswith("--add-data") for item in command))


if __name__ == "__main__":
    unittest.main()
