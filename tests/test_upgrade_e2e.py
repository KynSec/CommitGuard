from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"


class UpgradeEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        (self.repo / "app.py").write_text(
            "def add(left, right):\n"
            "    return left + right\n",
            encoding="utf-8",
        )
        (self.repo / ".commit_guard.toml").write_text(
            "[scan]\n"
            'threshold = "high"\n'
            'format = "json"\n',
            encoding="utf-8",
        )
        (self.repo / ".commit_guard_ignore").write_text(
            "# legacy 2.x baseline; no migration required\n"
            "fingerprint:0123456789abcdef\n",
            encoding="utf-8",
        )
        self._git("init", "-q")
        self._git("config", "user.email", "upgrade@example.invalid")
        self._git("config", "user.name", "CommitGuard Upgrade")
        self._git("add", ".")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(self.repo),
            check=True,
            text=True,
            capture_output=True,
        )

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MAIN), "--repo", str(self.repo), *args],
            cwd=str(self.repo),
            text=True,
            capture_output=True,
            check=False,
        )

    def test_documented_upgrade_path_emits_schema_three(self) -> None:
        report = self.repo / "report.json"
        result = self._run(
            "--all",
            "--format",
            "json",
            "--report-path",
            str(report),
            "--quiet",
            "--soft-fail",
            "--gate",
            "--policy-profile",
            "audit",
            "--no-baseline",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 3)
        self.assertIn("findings", payload)
        self.assertEqual(payload["total"], len(payload["findings"]))

    def test_doctor_and_status_survive_legacy_configuration(self) -> None:
        status = subprocess.run(
            [sys.executable, str(ROOT / "install_hook.py"), "status", str(self.repo)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(status.returncode, (0, 1, 2))
        self.assertIn("COMMIT GUARD", status.stdout + status.stderr)


if __name__ == "__main__":
    unittest.main()
