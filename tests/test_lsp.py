from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.lsp import (
    LanguageServer,
    path_to_uri,
    read_message,
    serve_stdio,
)

ROOT = Path(__file__).resolve().parents[1]


def frame(message: dict) -> bytes:
    body = json.dumps(message).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def messages(data: bytes) -> list[dict]:
    stream = io.BytesIO(data)
    result: list[dict] = []
    while True:
        message = read_message(stream)
        if message is None:
            return result
        result.append(message)


class LSPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        rules = self.root / "rules"
        rules.mkdir()
        (rules / "custom_rules.yaml").write_text(
            "rules:\n"
            "  - id: cg-test-token\n"
            "    description: Test token found\n"
            "    severity: high\n"
            "    category: secret\n"
            "    languages: [python]\n"
            "    regex: 'TOKEN_[A-Z]{4}'\n",
            encoding="utf-8",
        )
        self.uri = path_to_uri(self.root / "app.py")

    def tearDown(self):
        self.temp.cleanup()

    def test_initialize_open_and_code_action(self):
        stdin = io.BytesIO()
        for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": self.uri,
                        "languageId": "python",
                        "version": 1,
                        "text": "TOKEN_ABCD\n",
                    }
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/codeAction",
                "params": {
                    "textDocument": {"uri": self.uri},
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 10},
                    },
                    "context": {"diagnostics": []},
                },
            },
            {"jsonrpc": "2.0", "id": 3, "method": "shutdown"},
            {"jsonrpc": "2.0", "method": "exit"},
        ):
            stdin.write(frame(message))
        stdin.seek(0)
        stdout = io.BytesIO()
        self.assertEqual(serve_stdio(self.root, stdin, stdout), 0)
        output = messages(stdout.getvalue())
        by_id = {item["id"]: item for item in output if "id" in item}
        self.assertIn("codeActionProvider", by_id[1]["result"]["capabilities"])
        diagnostics = [
            item
            for item in output
            if item.get("method") == "textDocument/publishDiagnostics"
        ]
        self.assertTrue(diagnostics)
        finding = diagnostics[0]["params"]["diagnostics"][0]
        self.assertEqual(finding["code"], "cg-test-token")
        self.assertEqual(finding["source"], "commitguard")
        actions = by_id[2]["result"]
        self.assertEqual(actions[0]["command"]["command"], "commitguard.explain")
        self.assertIsNone(by_id[3]["result"])

    def test_change_and_close_clear_diagnostics(self):
        server = LanguageServer(self.root)
        stdout = io.BytesIO()
        server.handle(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": self.uri,
                        "languageId": "python",
                        "version": 1,
                        "text": "TOKEN_ABCD\n",
                    }
                },
            },
            stdout,
        )
        server.handle(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": self.uri, "version": 2},
                    "contentChanges": [{"text": "print('clean')\n"}],
                },
            },
            stdout,
        )
        server.handle(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didClose",
                "params": {"textDocument": {"uri": self.uri}},
            },
            stdout,
        )
        published = [
            item
            for item in messages(stdout.getvalue())
            if item.get("method") == "textDocument/publishDiagnostics"
        ]
        self.assertTrue(published[0]["params"]["diagnostics"])
        self.assertEqual(published[1]["params"]["diagnostics"], [])
        self.assertEqual(published[2]["params"]["diagnostics"], [])

    def test_main_lsp_entrypoint(self):
        process = subprocess.run(
            [sys.executable, str(ROOT / "install_hook.py"), "lsp", str(self.root)],
            input=frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + frame({"jsonrpc": "2.0", "method": "exit"}),
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
        output = messages(process.stdout)
        self.assertEqual(output[0]["id"], 1)
        self.assertEqual(output[0]["result"]["serverInfo"]["name"], "commitguard-lsp")

    def test_main_lsp_entrypoint_accepts_client_stdio_flag(self):
        process = subprocess.run(
            [
                sys.executable,
                str(ROOT / "install_hook.py"),
                "lsp",
                str(self.root),
                "--stdio",
            ],
            input=frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + frame({"jsonrpc": "2.0", "method": "exit"}),
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
        output = messages(process.stdout)
        self.assertEqual(output[0]["id"], 1)
        self.assertEqual(output[0]["result"]["serverInfo"]["name"], "commitguard-lsp")


if __name__ == "__main__":
    unittest.main()
