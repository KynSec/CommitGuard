from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.sca import (
    SIGNING_KEY_ENV,
    scan_dependencies,
    sign_snapshot,
    verify_snapshot_signature,
)

VULNERABILITY = {
    "id": "GHSA-signed-test",
    "aliases": ["CVE-2026-0001"],
    "summary": "Signed snapshot test vulnerability.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.32.0"}],
                }
            ],
        }
    ],
}


class SignedSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "requirements.txt").write_text(
            "requests==2.19.0\n", encoding="utf-8"
        )
        self.snapshot = self.root / ".commit_guard_osv.json"
        self.snapshot.write_text(
            json.dumps({"vulnerabilities": [VULNERABILITY]}), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_signed_snapshot_is_verified_and_scanned(self) -> None:
        with mock.patch.dict(os.environ, {SIGNING_KEY_ENV: "test-key"}):
            signature = sign_snapshot(self.snapshot)
            self.assertTrue(signature.is_file())
            verified, reason = verify_snapshot_signature(
                self.snapshot, required=True
            )
            self.assertTrue(verified, reason)
            result = scan_dependencies(
                self.root, require_snapshot_signature=True
            )
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].id, "GHSA-signed-test")

    def test_tampered_snapshot_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {SIGNING_KEY_ENV: "test-key"}):
            sign_snapshot(self.snapshot)
        self.snapshot.write_text(
            json.dumps({"vulnerabilities": []}), encoding="utf-8"
        )
        with mock.patch.dict(os.environ, {SIGNING_KEY_ENV: "test-key"}):
            result = scan_dependencies(
                self.root, require_snapshot_signature=True
            )
        self.assertEqual(result.vulnerabilities, ())
        self.assertTrue(
            any("signature" in warning for warning in result.warnings),
            result.warnings,
        )

    def test_required_signature_rejects_unsigned_snapshot(self) -> None:
        with mock.patch.dict(os.environ, {SIGNING_KEY_ENV: "test-key"}):
            result = scan_dependencies(
                self.root, require_snapshot_signature=True
            )
        self.assertEqual(result.vulnerabilities, ())
        self.assertTrue(
            any("unsigned" in warning for warning in result.warnings),
            result.warnings,
        )


if __name__ == "__main__":
    unittest.main()
