from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from core.pipelines import (
    PipelineError,
    detect_pipelines,
    list_pipelines,
    load_pipelines,
    run_pipeline,
)


def command(*args: str) -> str:
    return json.dumps(list(args))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, text: str) -> None:
        (self.root / ".commit_guard.toml").write_text(text, encoding="utf-8")

    def test_load_configured_pipelines(self):
        self.write_config(
            f"""
[pipelines.ok]
command = {command(sys.executable, "-c", "print('ok')")}
description = "smoke"
category = "test"
timeout = 30
cwd = "."
env = {{ CG_TEST = "1" }}
[pipelines.string-command]
command = "{sys.executable} -c print('string')"
"""
        )
        specs = load_pipelines(self.root)
        self.assertEqual(specs["ok"].category, "test")
        self.assertEqual(specs["ok"].env, {"CG_TEST": "1"})
        self.assertEqual(specs["ok"].source, "configured")
        self.assertEqual(specs["string-command"].command[0], sys.executable)

    def test_invalid_pipelines_are_rejected(self):
        cases = [
            "[pipelines]\nbad name = ['echo']\n",
            "[pipelines.x]\ncommand = []\n",
            "[pipelines.x]\ncommand = ['echo']\ntimeout = 0\n",
            "[pipelines.x]\ncommand = ['echo']\ncategory = 'nope'\n",
            "[pipelines.x]\ncommand = ['echo']\ncwd = '../outside'\n",
            "[pipelines.x]\ncommand = ['echo']\nenv = { 'bad key' = 'x' }\n",
        ]
        for text in cases:
            with self.subTest(text=text):
                self.write_config(text)
                with self.assertRaises(PipelineError):
                    load_pipelines(self.root)

    def test_run_success_environment_and_cwd(self):
        (self.root / "sub").mkdir()
        self.write_config(
            f"""
[pipelines.env]
command = {command(sys.executable, "-c", "import os; print(os.environ['CG_TEST'])")}
env = {{ CG_TEST = "hello" }}
[pipelines.cwd]
command = {command(sys.executable, "-c", "import os; print(os.path.basename(os.getcwd()))")}
cwd = "sub"
"""
        )
        env = run_pipeline(self.root, "env")
        self.assertTrue(env.to_dict()["ok"])
        self.assertIn("hello", env.stdout)
        cwd = run_pipeline(self.root, "cwd")
        self.assertIn("sub", cwd.stdout)

    def test_run_failure_timeout_and_missing_command(self):
        self.write_config(
            f"""
[pipelines.fail]
command = {command(sys.executable, "-c", "raise SystemExit(4)")}
[pipelines.slow]
command = {command(sys.executable, "-c", "import time; time.sleep(5)")}
timeout = 1
[pipelines.missing]
command = ["commit-guard-command-that-does-not-exist"]
"""
        )
        failed = run_pipeline(self.root, "fail")
        self.assertEqual(failed.exit_code, 4)
        self.assertFalse(failed.to_dict()["ok"])
        slow = run_pipeline(self.root, "slow")
        self.assertTrue(slow.timed_out)
        self.assertEqual(slow.exit_code, 124)
        missing = run_pipeline(self.root, "missing")
        self.assertEqual(missing.exit_code, 127)
        self.assertIn("command not found", missing.stderr)

    def test_detection_and_listing(self):
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_x.py").write_text("", encoding="utf-8")
        (self.root / "pyproject.toml").write_text(
            "[tool.ruff]\n[tool.mypy]\n", encoding="utf-8"
        )
        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"test": "node test.js", "build": "node build.js"}}),
            encoding="utf-8",
        )
        (self.root / "Makefile").write_text("check:\n\techo check\n", encoding="utf-8")
        (self.root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        detected = detect_pipelines(self.root)
        self.assertIn("python-test", detected)
        self.assertIn("python-lint", detected)
        self.assertIn("python-types", detected)
        self.assertIn("node-test", detected)
        self.assertIn("make-check", detected)
        self.assertIn("docker-build", detected)
        listed = list_pipelines(self.root)
        self.assertTrue(listed["detected"])
        self.assertEqual(listed["configured"], [])


if __name__ == "__main__":
    unittest.main()
