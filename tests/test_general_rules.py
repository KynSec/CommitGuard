# SPDX-License-Identifier: Apache-2.0
"""Tests for the general/DevSkim rule packs and their native metadata."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

import yaml

from core.engines.base import ScanContext
from core.engines.regex_engine import RegexEngine
from core.git_diff import DiffLine
from core.rule_loader import Rule, RuleSet, load_ruleset, rules_for_file
from core.scanner import scan_diff

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"


def line(code: str, path: str = "app.py", number: int = 1) -> DiffLine:
    return DiffLine(file_path=path, line_number=number, code_content=code)


class GeneralRuleTests(unittest.TestCase):
    ruleset: ClassVar[RuleSet]
    rules: ClassVar[dict[str, Rule]]

    @classmethod
    def setUpClass(cls) -> None:
        with (
            tempfile.TemporaryDirectory() as cache,
            mock.patch.dict(os.environ, {"COMMIT_GUARD_CACHE_DIR": cache}),
        ):
            cls.ruleset = load_ruleset(RULES_DIR, warn=False, use_cache=False)
        cls.rules = {rule.rule_id: rule for rule in cls.ruleset.rules}

    def test_devskim_pack_is_loaded_with_metadata(self) -> None:
        devskim = [rule for rule in self.ruleset.rules if rule.source == "devskim"]
        self.assertEqual(len(devskim), 115)
        self.assertTrue(all(rule.category for rule in devskim))
        self.assertTrue(all(rule.confidence in {"high", "medium", "low"} for rule in devskim))
        self.assertIn("devskim-DS205001", self.rules)

    def test_every_generated_language_has_a_loader_mapping(self) -> None:
        from core.rule_loader import _SEMGREP_LANG_TO_EXT

        for path in sorted((RULES_DIR / "general" / "devskim").glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for entry in data["rules"]:
                for language in entry.get("languages", []):
                    self.assertIn(
                        language.lower(),
                        _SEMGREP_LANG_TO_EXT,
                        f"{entry['id']} uses unmapped language {language!r}",
                    )

    def test_filename_tokens_scope_general_rules(self) -> None:
        dotenv_rule = self.rules["devskim-DS205001"]
        for path in (".env", ".env.local", "requirements.txt", "web.config", "packages.config"):
            self.assertIn(
                dotenv_rule,
                rules_for_file([dotenv_rule], path),
                f"{path} should match language tokens {dotenv_rule.languages}",
            )
        self.assertFalse(rules_for_file([dotenv_rule], "index.html"))

    def test_curated_web_rule_sets_category_and_confidence(self) -> None:
        findings = scan_diff(
            [line('requests.get(request.args.get("url"))')],
            [self.rules["cg-web-ssrf-request-url"]],
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.source, "custom")
        self.assertEqual(finding.category, "web")
        self.assertEqual(finding.confidence, "medium")

    def test_devskim_secret_rules_are_marked_and_redacted(self) -> None:
        token_rule = self.rules["devskim-DS173239"]
        self.assertTrue(token_rule.is_secret)
        self.assertEqual(token_rule.category, "secret")
        self.assertFalse(self.rules["devskim-DS114352"].is_secret)
        token = "ghp_Ab9xK2mQ7pR4sT8vW1yZ6nC3dF5gH0jL2kM9"
        findings = scan_diff(
            [line(f'TOKEN = "{token}"')],
            [token_rule],
            filter_placeholders=False,
        )
        self.assertEqual(len(findings), 1)
        self.assertNotIn(token, findings[0].redacted_code)
        self.assertIn(token, findings[0].display_code(show_secrets=True))

    def test_regex_engine_preserves_rule_confidence(self) -> None:
        rule = self.rules["cg-authz-role-from-request"]
        context = ScanContext(
            repo_root=ROOT,
            diff_lines=(line('role = request.POST.get("role")'),),
            rules=(rule,),
        )
        result = RegexEngine().run(context)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].category, "authz")
        self.assertEqual(result.findings[0].confidence, "low")

    def test_curated_rules_match_high_signal_samples(self) -> None:
        cases = (
            ("cg-web-open-redirect-untrusted", 'redirect(request.args["next"])', "app.py"),
            (
                "cg-web-ssti-user-template",
                'render_template_string(request.args["t"])',
                "app.py",
            ),
            (
                "cg-web-nosql-injection-request-body",
                'db.users.find({ username: req.body.username })',
                "app.js",
            ),
            (
                "cg-authz-mass-assignment-kwargs",
                'User.objects.create(**request.POST)',
                "app.py",
            ),
            (
                "cg-authz-object-lookup-request-id",
                'Post.objects.get(id=request.GET["id"])',
                "app.py",
            ),
            ("cg-authz-role-from-request", 'role = request.POST.get("role")', "app.py"),
            ("cg-deser-python-torch-load", 'torch.load(model_path)', "app.py"),
            ("cg-deser-python-joblib-load", 'joblib.load(model_path)', "app.py"),
            (
                "cg-deser-java-invoker-transformer",
                'new InvokerTransformer("exec")',
                "app.java",
            ),
        )
        for rule_id, code, path in cases:
            with self.subTest(rule_id=rule_id):
                findings = scan_diff([line(code, path)], [self.rules[rule_id]])
                self.assertEqual(len(findings), 1, code)

    def test_context_based_general_rules(self) -> None:
        gha = self.rules["cg-supply-gha-pwn-request"]
        lines = [
            line("on: pull_request_target", ".github/workflows/ci.yml", 1),
            line("jobs:", ".github/workflows/ci.yml", 2),
            line("  test:", ".github/workflows/ci.yml", 3),
            line("    steps:", ".github/workflows/ci.yml", 4),
            line("      - uses: actions/checkout@v4", ".github/workflows/ci.yml", 5),
        ]
        findings = scan_diff(lines[:1], [gha], file_lines={lines[0].file_path: [x.code_content for x in lines]})
        self.assertEqual(len(findings), 1)

        race = self.rules["cg-authz-race-check-then-act"]
        lines = [
            line("if not os.path.exists(path):", "app.py", 1),
            line("    open(path, 'w').write(data)", "app.py", 2),
        ]
        findings = scan_diff(
            lines[:1],
            [race],
            file_lines={lines[0].file_path: [x.code_content for x in lines]},
        )
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
