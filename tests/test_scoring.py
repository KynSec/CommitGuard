"""Tests for core/scoring.py: risk priority, corroboration, secret score, and typosquatting."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from core.scoring import (
    calculate_commit_risk_index,
    calculate_entropy_zscore,
    calculate_file_blast_radius,
    calculate_risk_priority,
    calculate_secret_score,
    calculate_security_debt,
    check_typosquatting,
    corroboration_score,
    damerau_levenshtein_distance,
    score_finding_priority,
)


class ScoringTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # Equation 1: Risk Priority
    # priority = 100 * impact * exploitability * exposure * reachability * confidence
    # -------------------------------------------------------------------------
    def test_risk_priority_bounds_and_calculation(self):
        # 100 * 1.0 * 1.0 * 1.0 * 1.0 * 1.0 = 100.0
        self.assertEqual(
            calculate_risk_priority(
                impact=1.0,
                exploitability=1.0,
                exposure=1.0,
                reachability=1.0,
                confidence=1.0,
            ),
            100.0,
        )
        # 100 * 0.8 * 0.7 * 1.0 * 0.5 * 0.75 = 21.0
        self.assertAlmostEqual(
            calculate_risk_priority(
                impact=0.8,
                exploitability=0.7,
                exposure=1.0,
                reachability=0.5,
                confidence=0.75,
            ),
            21.0,
        )
        # Clamped to [0, 100]
        self.assertEqual(
            calculate_risk_priority(
                impact=2.0,
                exploitability=2.0,
                exposure=2.0,
                reachability=2.0,
                confidence=2.0,
            ),
            100.0,
        )
        self.assertEqual(
            calculate_risk_priority(
                impact=-0.5,
                exploitability=1.0,
                exposure=1.0,
                reachability=1.0,
                confidence=1.0,
            ),
            0.0,
        )

    def test_score_finding_priority(self):
        finding = SimpleNamespace(
            severity="critical",
            cwe="CWE-78",
            category="sast",
            file="app/routes/api.py",
            confidence="high",
            tags=("rce", "injection"),
        )
        score = score_finding_priority(finding, reachability=1.0)
        self.assertGreater(score, 50.0)

        # Test file with low exposure
        test_finding = SimpleNamespace(
            severity="low",
            cwe=None,
            category="quality",
            file="tests/unit/test_app.py",
            confidence="low",
            tags=(),
        )
        test_score = score_finding_priority(test_finding)
        self.assertLess(test_score, 10.0)

    # -------------------------------------------------------------------------
    # Equation 2: Duplicate / Corroboration Scoring
    # effective = min(100, max(rule_scores) + 10 * (independent_rules - 1))
    # -------------------------------------------------------------------------
    def test_corroboration_scoring(self):
        # Empty scores
        self.assertEqual(corroboration_score([]), 0.0)

        # Single rule match
        self.assertEqual(corroboration_score([65.0]), 65.0)

        # Multiple corroborated rules: max(70, 60) + 10 * (2 - 1) = 80.0
        self.assertEqual(corroboration_score([60.0, 70.0]), 80.0)

        # Three rules: max(85, 80, 75) + 10 * (3 - 1) = 100 (capped at 100)
        self.assertEqual(corroboration_score([75.0, 80.0, 85.0]), 100.0)

        # With explicit independent rules count
        self.assertEqual(
            corroboration_score([50.0], independent_rules=3),
            70.0,
        )

    # -------------------------------------------------------------------------
    # Equation 3: Secret Confidence
    # secret_score = 0.35*entropy_norm + 0.25*length_score + 0.20*charset_score + 0.20*issuer_prefix - placeholder_penalty
    # -------------------------------------------------------------------------
    def test_calculate_secret_score(self):
        # High-entropy real-looking secret with issuer prefix
        api_key = "sk-proj-9A8b7C6d5E4f3G2h1J0kLmNoPqRsTuVw"
        score = calculate_secret_score(api_key, issuer_prefix_matched=True)
        self.assertGreater(score, 0.75)

        # Obvious placeholder
        placeholder = "your_api_key_here_placeholder_xxxx"
        low_score = calculate_secret_score(placeholder)
        self.assertLess(low_score, 0.40)

        # Empty string
        self.assertEqual(calculate_secret_score(""), 0.0)

    # -------------------------------------------------------------------------
    # Equation 4: Typosquatting (Damerau-Levenshtein)
    # suspicious if Damerau-Levenshtein(name, popular_package) <= max(1, len(name)//6)
    # -------------------------------------------------------------------------
    def test_damerau_levenshtein_distance(self):
        # Identity
        self.assertEqual(damerau_levenshtein_distance("requests", "requests"), 0)
        # Transposition (adjacent characters swapped)
        self.assertEqual(damerau_levenshtein_distance("reqeusts", "requests"), 1)
        # Insertion
        self.assertEqual(damerau_levenshtein_distance("requests1", "requests"), 1)
        # Deletion
        self.assertEqual(damerau_levenshtein_distance("requsts", "requests"), 1)
        # Substitution
        self.assertEqual(damerau_levenshtein_distance("requxsts", "requests"), 1)

    def test_check_typosquatting(self):
        # Common typosquat: reqeusts vs requests
        is_typo, target, dist = check_typosquatting("reqeusts", ecosystem="pypi")
        self.assertTrue(is_typo)
        self.assertEqual(target, "requests")
        self.assertEqual(dist, 1)

        # Legitimate exact match is NOT typosquat
        is_typo, _, _ = check_typosquatting("requests", ecosystem="pypi")
        self.assertFalse(is_typo)

        # npm package typosquat: exppress vs express
        is_typo, target, dist = check_typosquatting("exppress", ecosystem="npm")
        self.assertTrue(is_typo)
        self.assertEqual(target, "express")
        self.assertEqual(dist, 1)

        # Totally unrelated package name
        is_typo, _, _ = check_typosquatting("my_custom_internal_library", ecosystem="pypi")
        self.assertFalse(is_typo)


    def test_calculate_commit_risk_index(self):
        # Empty findings
        self.assertEqual(calculate_commit_risk_index([]), 0.0)

        # Single finding with 80 priority -> 80%
        f1 = SimpleNamespace(risk_priority=80.0)
        self.assertEqual(calculate_commit_risk_index([f1]), 80.0)

        # Three medium findings with 35.0 priority -> 100 * (1 - (1 - 0.35)^3) = 72.5%
        f_med = [SimpleNamespace(risk_priority=35.0) for _ in range(3)]
        self.assertAlmostEqual(calculate_commit_risk_index(f_med), 72.5, places=1)

    def test_calculate_file_blast_radius(self):
        # Mock dependency graph with reverse importer tree:
        # core.py is imported by service.py (depth 1), which is imported by api.py (depth 2)
        graph = SimpleNamespace(
            reverse={
                "core.py": {"service.py"},
                "service.py": {"api.py"},
            }
        )
        # Blast radius for core.py: 1.0 + (1 / 1^1.5) + (1 / 2^1.5) = 1.0 + 1.0 + 0.35 = 2.35
        radius = calculate_file_blast_radius("core.py", graph, alpha=1.5)
        self.assertAlmostEqual(radius, 2.35, places=2)

        # Leaf node with no dependents
        leaf_radius = calculate_file_blast_radius("api.py", graph)
        self.assertEqual(leaf_radius, 1.0)

    def test_calculate_entropy_zscore(self):
        file_lines = [
            "import os",
            "import sys",
            "def hello():",
            "    print('simple english text for baseline')",
        ]
        # Low entropy token in normal file
        low_z = calculate_entropy_zscore("hello", file_lines)
        # High entropy random secret in normal file
        high_token = "4f8a9e2c1b7d3e6f9a0c2e5b8d1f4a7c"
        high_z = calculate_entropy_zscore(high_token, file_lines)
        self.assertGreater(high_z, low_z)

    def test_calculate_security_debt(self):
        f_secret = SimpleNamespace(category="secret", fix=None)
        f_sast_fixable = SimpleNamespace(category="sast", fix={"pattern": "a", "replacement": "b"})
        debt = calculate_security_debt([f_secret, f_sast_fixable])
        # Gross = 20.0 (secret) + 25.0 (sast) = 45.0
        self.assertEqual(debt["gross_debt_minutes"], 45.0)
        # Sast fixable saves 25.0 * 0.85 = 21.25 -> net sast is 3.75 -> net total is 23.8
        self.assertEqual(debt["saved_by_autofix_minutes"], 21.2)
        self.assertEqual(debt["net_debt_minutes"], 23.8)


if __name__ == "__main__":
    unittest.main()

