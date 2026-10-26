from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from core.scanner import Finding
from core.triage import (
    TriageError,
    TriageState,
    apply_triage,
    audit_triage,
    load_triage,
    prune_triage,
    save_triage,
    set_entry,
)


def finding(**overrides) -> Finding:
    payload = {
        "file": "app.py",
        "line_number": 1,
        "rule_id": "cg-test",
        "description": "test",
        "severity": "high",
        "source": "gitleaks",
        "flagged_code": "test",
        "fingerprint": "aaaaaaaaaaaaaaaa",
        "tags": ("secret",),
        "cwe": "CWE-798",
    }
    payload.update(overrides)
    return Finding(**payload)


class TriageTests(unittest.TestCase):
    def test_set_requires_owner_and_reason(self):
        with self.assertRaises(TriageError):
            set_entry(
                TriageState(),
                fingerprint="a" * 16,
                triage_state="accepted",
                reason="legacy",
            )
        with self.assertRaises(TriageError):
            set_entry(
                TriageState(),
                fingerprint="a" * 16,
                triage_state="accepted",
                owner="@team",
            )

    def test_set_and_roundtrip(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="accepted",
            owner="@team-security",
            reason="Legacy helper; ticket tracked.",
            ticket="SEC-1",
            expires="2027-01-31",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "triage.yaml"
            save_triage(state, path)
            loaded = load_triage(Path(directory), path)
        self.assertEqual(loaded.entries[0].owner, "@team-security")
        self.assertEqual(loaded.entries[0].expires, "2027-01-31")

    def test_conflicting_states_are_an_error(self):
        text = """
version: 1
entries:
  - fingerprint: aaaaaaaaaaaaaaaa
    state: accepted
    owner: "@a"
    reason: "one"
  - fingerprint: aaaaaaaaaaaaaaaa
    state: false_positive
    owner: "@b"
    reason: "two"
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".commit_guard" / "triage.yaml"
            path.parent.mkdir()
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(TriageError):
                load_triage(Path(directory))

    def test_apply_suppresses_accepted(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="accepted",
            owner="@team",
            reason="accepted debt",
            expires="2099-01-01",
        )
        result = apply_triage([finding()], state)
        self.assertEqual(result.visible, ())
        self.assertEqual(result.suppressed_total, 1)

    def test_expired_entry_becomes_visible(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="accepted",
            owner="@team",
            reason="expired debt",
            expires="2020-01-01",
        )
        result = apply_triage([finding()], state, today=date(2026, 1, 1))
        self.assertEqual(len(result.visible), 1)
        self.assertTrue(result.visible[0].provenance["triage_expired"])
        self.assertEqual(len(result.expired), 1)

    def test_fixed_entry_still_present_is_visible(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="fixed",
        )
        result = apply_triage([finding()], state)
        self.assertEqual(len(result.visible), 1)
        self.assertTrue(result.visible[0].provenance["triage_fixed_still_present"])

    def test_prune_removes_fixed_absent(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="fixed",
        )
        state, removed = prune_triage(state, set())
        self.assertEqual(removed, ("a" * 16,))
        self.assertEqual(state.entries, ())

    def test_audit_reports_stale_and_expired(self):
        state = set_entry(
            TriageState(),
            fingerprint="a" * 16,
            triage_state="accepted",
            owner="@team",
            reason="debt",
            expires="2020-01-01",
        )
        issues = audit_triage(state, set(), today=date(2026, 1, 1))
        self.assertTrue(any("expired" in issue for issue in issues))
        self.assertTrue(any("no current finding" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
