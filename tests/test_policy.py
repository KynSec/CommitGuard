from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from core.policy import (
    Policy,
    PolicyError,
    evaluate_gate,
    explain_finding,
    load_policy,
)
from core.scanner import Finding


def finding(**overrides) -> Finding:
    payload = {
        "file": "src/app.py",
        "line_number": 4,
        "rule_id": "cg-test-rule",
        "description": "test finding",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": "test",
        "fingerprint": "aaaaaaaaaaaaaaaa",
        "tags": ("secret",),
        "cwe": "CWE-798",
    }
    payload.update(overrides)
    return Finding(**payload)


class PolicyTests(unittest.TestCase):
    def test_default_profile(self):
        policy = Policy()
        self.assertEqual(policy.profile, "balanced")
        self.assertEqual(policy.threshold, "high")
        self.assertTrue(policy.ratchet)

    def test_load_policy_from_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".commit_guard.toml").write_text(
                """
[gate]
profile = "strict"
threshold = "medium"
fail_on = "all"
ratchet = false
max_new = { critical = 0, high = 1, medium = 2 }
[gate.budgets.python]
high = 3
[gate.budgets."src/payments/**"]
critical = 0
""",
                encoding="utf-8",
            )
            policy = load_policy(root)
        self.assertEqual(policy.profile, "strict")
        self.assertEqual(policy.threshold, "medium")
        self.assertEqual(policy.fail_on, "all")
        self.assertFalse(policy.ratchet)
        self.assertEqual(policy.max_new["high"], 1)
        self.assertEqual(policy.category_budgets["python"]["high"], 3)
        self.assertEqual(policy.path_budgets["src/payments/**"]["critical"], 0)

    def test_invalid_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".commit_guard.toml").write_text(
                "[gate]\nthreshold = 'urgent'\n", encoding="utf-8"
            )
            with self.assertRaises(PolicyError):
                load_policy(root)
            (root / ".commit_guard.toml").write_text(
                "[gate]\nunknown_key = true\n", encoding="utf-8"
            )
            with self.assertRaises(PolicyError):
                load_policy(root)

    def test_existing_debt_is_allowed(self):
        item = finding(baseline_state="unchanged")
        result = evaluate_gate([item], Policy())
        self.assertTrue(result.passed)
        self.assertEqual(result.new_findings, 0)

    def test_baseline_fingerprint_allows_finding(self):
        item = finding()
        result = evaluate_gate(
            [item], Policy(), baseline_fingerprints={item.fingerprint}
        )
        self.assertTrue(result.passed)

    def test_new_high_finding_blocks_and_ratchets(self):
        result = evaluate_gate([finding()], Policy())
        self.assertFalse(result.passed)
        self.assertEqual(result.blocking, 1)
        self.assertTrue(any(reason["rule_id"] == "policy/ratchet" for reason in result.reasons))

    def test_medium_finding_can_pass_threshold(self):
        result = evaluate_gate([finding(severity="medium")], Policy())
        self.assertTrue(result.passed)
        self.assertEqual(result.new_findings, 1)

    def test_severity_budget_fails_below_threshold(self):
        policy = Policy(threshold="high", max_new={"low": 0})
        result = evaluate_gate([finding(severity="low")], policy)
        self.assertFalse(result.passed)
        self.assertTrue(any("budget exceeded" in reason["reason"] for reason in result.reasons))

    def test_path_and_category_budgets(self):
        policy = Policy(
            threshold="high",
            path_budgets={"src/payments/**": {"high": 0}},
            max_new={},
        )
        item = finding(file="src/payments/charge.py", severity="high")
        result = evaluate_gate([item], policy)
        self.assertTrue(any("budget for src/payments/**" in reason["reason"] for reason in result.reasons))
        category_policy = Policy(
            threshold="high",
            category_budgets={"secret": {"high": 0}},
            max_new={},
        )
        result = evaluate_gate([finding()], category_policy)
        self.assertTrue(any("category secret" in reason["reason"] for reason in result.reasons))

    def test_audit_profile_never_blocks(self):
        result = evaluate_gate([finding()], Policy(profile="audit", enforce=False))
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, ())

    def test_expired_triage_blocks(self):
        item = finding(provenance={"triage_expired": True})
        result = evaluate_gate([item], Policy())
        self.assertFalse(result.passed)
        self.assertTrue(any("expired triage" in reason["reason"] for reason in result.reasons))

    def test_fixed_triage_still_present_blocks(self):
        item = finding(provenance={"triage_fixed_still_present": True})
        result = evaluate_gate([item], Policy())
        self.assertFalse(result.passed)

    def test_explain_chain(self):
        item = finding()
        result = explain_finding(item, Policy(), baseline_fingerprints=set())
        stages = [stage["stage"] for stage in result["chain"]]
        self.assertEqual(stages, ["inline", "triage", "baseline", "severity", "gate"])
        self.assertFalse(result["gate"]["passed"])

    def test_explicit_threshold_overrides_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".commit_guard.toml").write_text(
                "[gate]\nthreshold = 'low'\n", encoding="utf-8"
            )
            policy = load_policy(root, threshold="critical")
        self.assertEqual(policy.threshold, "critical")

    def test_strict_profile_blocks_existing_debt(self):
        item = finding(baseline_state="unchanged")
        result = evaluate_gate([item], replace(Policy(profile="strict"), fail_on="all"))
        self.assertFalse(result.passed)


if __name__ == "__main__":
    unittest.main()
