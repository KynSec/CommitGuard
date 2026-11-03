from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gui_actions as actions
from core.rule_loader import Rule, RuleSet, SkippedRule
from core.scan_profiles import (
    PathSelection,
    ProfileError,
    RuleSelection,
    ScanProfile,
    filter_ruleset,
    load_scan_profiles,
    merge_selection,
    resolve_profile,
    scan_profiles_doc_text,
    selected_ast_rule_ids,
)

GIT = shutil.which("git")
ROOT = Path(__file__).resolve().parents[1]


PROFILE_YAML = """\
version: 1
profiles:
  src-only:
    description: Only source paths.
    mode: repo
    paths:
      include: ["src/**"]
      exclude: ["**/generated/**"]
    rules:
      sources: [custom, python_ast]
      include: ["cg-*"]
      exclude: ["*-deprecated"]
      severities: [critical, high]
  staged-secrets:
    description: Staged secret scan.
    mode: staged
    rules:
      sources: [gitleaks]
"""


class ScanProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.rules_dir = self.root / "rules"
        self.rules_dir.mkdir()
        self.path = self.rules_dir / "scan_profiles.yaml"
        self.path.write_text(PROFILE_YAML, encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_bundled_profiles_load(self):
        profiles = load_scan_profiles(ROOT / "rules")
        self.assertIn("default", profiles)
        self.assertIn("full-repo", profiles)
        self.assertIn("app-code", profiles)
        self.assertEqual(profiles["full-repo"].mode, "repo")

    def test_missing_default_file_returns_no_profiles(self):
        empty = self.root / "empty-rules"
        empty.mkdir()
        self.assertEqual(load_scan_profiles(empty), {})

    def test_explicit_missing_file_raises(self):
        with self.assertRaises(ProfileError):
            load_scan_profiles(self.rules_dir, self.root / "missing.yaml")

    def test_loads_profiles_and_to_dict(self):
        profiles = load_scan_profiles(self.rules_dir)
        profile = profiles["src-only"]
        self.assertEqual(profile.mode, "repo")
        self.assertEqual(profile.include, ("src/**",))
        self.assertEqual(profile.rule_sources, ("custom", "python_ast"))
        self.assertEqual(profile.rule_severities, ("critical", "high"))
        payload = profile.to_dict()
        self.assertEqual(payload["paths"]["include"], ["src/**"])
        self.assertEqual(payload["rules"]["sources"], ["custom", "python_ast"])

    def test_invalid_mode_is_rejected(self):
        self.path.write_text(
            "profiles:\n  bad:\n    mode: sometimes\n", encoding="utf-8"
        )
        with self.assertRaises(ProfileError):
            load_scan_profiles(self.rules_dir)

    def test_invalid_severity_is_rejected(self):
        self.path.write_text(
            "profiles:\n  bad:\n    rules:\n      severities: [severe]\n",
            encoding="utf-8",
        )
        with self.assertRaises(ProfileError):
            load_scan_profiles(self.rules_dir)

    def test_invalid_profile_name_is_rejected(self):
        self.path.write_text("profiles:\n  'bad name': {}\n", encoding="utf-8")
        with self.assertRaises(ProfileError):
            load_scan_profiles(self.rules_dir)

    def test_resolve_profile(self):
        profiles = load_scan_profiles(self.rules_dir)
        self.assertIsNone(resolve_profile(profiles, None))
        self.assertEqual(resolve_profile(profiles, "default").name, "default")
        self.assertEqual(resolve_profile(profiles, "src-only").name, "src-only")
        with self.assertRaises(ProfileError):
            resolve_profile(profiles, "nope")

    def test_merge_precedence_and_additive_excludes(self):
        profile = ScanProfile(
            name="p",
            mode="repo",
            include=("src/**",),
            exclude=("vendor/**",),
            rule_sources=("custom",),
            include_rules=("cg-*",),
            exclude_rules=("*-old",),
            rule_severities=("high",),
        )
        selection = merge_selection(
            profile,
            include=("tests/**",),
            exclude=("**/generated/**",),
            rule_sources=("gitleaks",),
            include_rules=("gitleaks-*",),
            exclude_rules=("gitleaks-test-*",),
            rule_severities=("critical",),
        )
        self.assertEqual(selection.include, ("tests/**",))
        self.assertEqual(selection.exclude, ("vendor/**", "**/generated/**"))
        self.assertEqual(selection.rules.sources, ("gitleaks",))
        self.assertEqual(selection.rules.include, ("gitleaks-*",))
        self.assertEqual(selection.rules.exclude, ("*-old", "gitleaks-test-*"))
        self.assertEqual(selection.rules.severities, ("critical",))
        self.assertEqual(selection.to_dict()["profile"], "p")

    def test_path_selection(self):
        selection = PathSelection(include=("src/**",), exclude=("**/generated/**",))
        self.assertTrue(selection.matches("src/app.py"))
        self.assertTrue(selection.matches(Path("src/nested/app.py")))
        self.assertFalse(selection.matches("src/generated/code.py"))
        self.assertFalse(selection.matches("tests/app.py"))

    def test_rule_selection_matches_sources_globs_and_severity(self):
        selection = RuleSelection(
            sources=("semgrep:python",),
            include=("rule-*",),
            exclude=("*-test",),
            severities=("high", "critical"),
        )
        self.assertTrue(selection.matches("rule-a", "semgrep:python", "high"))
        self.assertFalse(selection.matches("rule-test", "semgrep:python", "high"))
        self.assertFalse(selection.matches("other", "semgrep:python", "high"))
        self.assertFalse(selection.matches("rule-a", "custom", "high"))
        self.assertFalse(selection.matches("rule-a", "semgrep:python", "low"))
        broad = RuleSelection(sources=("semgrep",))
        self.assertTrue(broad.matches_source("semgrep:python"))

    def test_filter_ruleset(self):
        ruleset = RuleSet(
            rules=(
                Rule("cg-a", "", "high", re.compile("a"), "custom"),
                Rule("gitleaks-a", "", "critical", re.compile("b"), "gitleaks"),
                Rule("cg-skip", "", "low", re.compile("c"), "custom"),
            ),
            skipped=(SkippedRule("bad", "custom", "bad"),),
        )
        filtered = filter_ruleset(
            ruleset,
            RuleSelection(sources=("custom",), include=("cg-*",), exclude=("*-skip",)),
        )
        self.assertEqual([rule.rule_id for rule in filtered.rules], ["cg-a"])
        self.assertEqual(filtered.skipped, ruleset.skipped)

    def test_selected_ast_rule_ids(self):
        self.assertIsNone(selected_ast_rule_ids(RuleSelection()))
        selected = selected_ast_rule_ids(RuleSelection(sources=("python_ast",)))
        self.assertTrue(selected)
        self.assertTrue(all("js-ast" not in rule_id for rule_id in selected))

    def test_doc_text_is_bundled(self):
        text = scan_profiles_doc_text()
        self.assertIn("Determinant scan profiles", text)
        self.assertIn("--list-profiles", text)


@unittest.skipUnless(GIT, "git is required")
class GuiScanProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / "main.py").write_text("# fake engine\n", encoding="utf-8")
        rules = self.root / "rules"
        rules.mkdir()
        (rules / "scan_profiles.yaml").write_text(PROFILE_YAML, encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_scan_profiles_action(self):
        data = actions.scan_profiles(self.root, self.root / "main.py")
        self.assertTrue(data["ok"])
        self.assertTrue(data["exists"])
        self.assertEqual([item["name"] for item in data["profiles"]], ["src-only", "staged-secrets"])

    def test_scan_profiles_action_reports_invalid_repo_config(self):
        (self.root / ".commit_guard.toml").write_text("[scan\n", encoding="utf-8")
        with self.assertRaises(actions.ActionError):
            actions.scan_profiles(self.root, self.root / "main.py")

    def test_missing_default_profiles_file_is_empty(self):
        (self.root / "rules" / "scan_profiles.yaml").unlink()
        data = actions.scan_profiles(self.root, self.root / "main.py")
        self.assertEqual(data["profiles"], [])
        self.assertFalse(data["exists"])

    def test_build_scan_command_profile_flags(self):
        command = actions.build_scan_command(
            self.root / "main.py",
            self.root,
            self.root / "report.json",
            {
                "mode": "profile",
                "profile": "src-only",
                "include": "src/**, tests/**",
                "exclude": ["vendor/**", "**/generated/**"],
                "rule_include": "cg-*",
                "rule_exclude": "*-old",
                "rule_sources": "custom,python_ast",
                "rule_severities": "critical,high",
            },
        )
        self.assertEqual(command[command.index("--profile") + 1], "src-only")
        self.assertNotIn("--all", command)
        self.assertNotIn("--staged", command)
        self.assertEqual(command.count("--include"), 2)
        self.assertEqual(command.count("--exclude"), 2)
        self.assertEqual(command[command.index("--rule") + 1], "cg-*")
        self.assertEqual(command[command.index("--skip-rule") + 1], "*-old")
        self.assertEqual(command[command.index("--rule-source") + 1], "custom")
        self.assertEqual(command[command.index("--rule-severity") + 1], "critical")

    def test_options_reject_flags(self):
        with self.assertRaises(actions.ActionError):
            actions.build_scan_command(
                self.root / "main.py",
                self.root,
                self.root / "report.json",
                {"mode": "profile", "include": "--all"},
            )


if __name__ == "__main__":
    unittest.main()
