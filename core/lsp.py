"""Minimal stdio Language Server Protocol implementation.

The server deliberately scans only the document it receives.  It never walks
the repository, never opens a socket, and never executes a rule-provided
command.  Diagnostics use the same rule loader and scanner as the CLI.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

from core.git_diff import DiffLine
from core.rule_loader import RuleSet, load_ruleset
from core.scanner import Finding, scan_diff

_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
_SEVERITY = {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 3,
}
_DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


class LSPError(ValueError):
    """Raised when a framed message is malformed."""


def uri_to_path(uri: str) -> Path | None:
    parsed = urlparse(uri)
    if parsed.scheme not in {"", "file"}:
        return None
    path = unquote(parsed.path)
    if parsed.scheme == "file" and parsed.netloc:
        path = f"//{parsed.netloc}{path}"
    return Path(path)


def path_to_uri(path: str | Path) -> str:
    return Path(path).expanduser().resolve().as_uri()


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            break
        try:
            text = line.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise LSPError("invalid LSP header encoding") from exc
        if ":" not in text:
            raise LSPError(f"invalid LSP header: {text!r}")
        name, value = text.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    try:
        length = int(headers.get("content-length", ""))
    except ValueError as exc:
        raise LSPError("missing or invalid Content-Length header") from exc
    if length < 0 or length > _MAX_MESSAGE_BYTES:
        raise LSPError("message is too large")
    body = stream.read(length)
    if len(body) != length:
        return None
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LSPError(f"invalid JSON-RPC body: {exc}") from exc
    return message if isinstance(message, dict) else None


def write_message(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def _range(line: int, length: int, start: int = 0) -> dict[str, Any]:
    return {
        "start": {"line": max(0, line - 1), "character": max(0, start)},
        "end": {"line": max(0, line - 1), "character": max(0, length)},
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


@dataclass
class LanguageServer:
    repo_root: Path = field(default_factory=Path.cwd)
    rules: RuleSet | None = None
    documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    diagnostics: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    shutdown_requested: bool = False

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).expanduser().resolve()

    def _load_rules(self) -> RuleSet:
        if self.rules is not None:
            return self.rules
        candidates = (
            self.repo_root / "rules",
            self.repo_root / ".commit_guard" / "rules",
            _DEFAULT_RULES,
        )
        for candidate in candidates:
            if (candidate / "custom_rules.yaml").is_file() or list(
                candidate.glob("*.yaml")
            ):
                self.rules = load_ruleset(candidate, warn=False, use_cache=False)
                return self.rules
        self.rules = RuleSet(rules=())
        return self.rules

    def _diagnostics_for(self, text: str, uri: str) -> list[dict[str, Any]]:
        path = uri_to_path(uri)
        if path is None:
            return []
        try:
            display_path = path.resolve().relative_to(self.repo_root).as_posix()
        except (OSError, ValueError):
            display_path = path.name
        lines = text.splitlines()
        diff_lines = [
            DiffLine(file_path=display_path, line_number=number, code_content=line)
            for number, line in enumerate(lines, start=1)
        ]
        try:
            ruleset = self._load_rules()
            findings = scan_diff(
                diff_lines,
                ruleset.rules,
                allowlist_regexes=ruleset.line_allowlist,
                allowlist_path_regexes=ruleset.path_allowlist,
                file_lines={display_path: lines},
            )
        except Exception:  # noqa: BLE001 - one bad rule must not kill the editor
            return []
        return [self._diagnostic(finding, lines) for finding in findings]

    def _diagnostic(
        self, finding: Finding, lines: list[str]
    ) -> dict[str, Any]:
        line_index = max(0, finding.line_number - 1)
        line_text = lines[line_index] if line_index < len(lines) else finding.flagged_code
        start = max(0, (finding.column or 1) - 1)
        end = (
            finding.end_column
            if finding.end_column is not None
            else max(start + 1, len(line_text))
        )
        diagnostic: dict[str, Any] = {
            "range": _range(finding.line_number, end, start),
            "severity": _SEVERITY.get(finding.severity, 2),
            "code": finding.rule_id,
            "source": "commitguard",
            "message": finding.description,
            "data": {
                "fingerprint": finding.fingerprint,
                "category": finding.category,
                "confidence": finding.confidence,
                "fix": finding.fix,
                "references": list(finding.references),
            },
        }
        return diagnostic

    def _publish(self, uri: str, stdout: BinaryIO) -> None:
        write_message(
            stdout,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": uri,
                    "diagnostics": self.diagnostics.get(uri, []),
                },
            },
        )

    def _code_actions(self, params: Mapping[str, Any]) -> list[dict[str, Any]]:
        uri = str(params.get("textDocument", {}).get("uri") or "")
        actions: list[dict[str, Any]] = []
        seen: set[str] = set()
        for diagnostic in self.diagnostics.get(uri, []):
            data = diagnostic.get("data") or {}
            fingerprint = str(data.get("fingerprint") or diagnostic.get("code") or "")
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            rule_id = str(diagnostic.get("code") or "rule")
            actions.append(
                {
                    "title": f"CommitGuard: explain {rule_id}",
                    "kind": "quickfix",
                    "diagnostics": [diagnostic],
                    "command": {
                        "title": "Explain finding",
                        "command": "commitguard.explain",
                        "arguments": [rule_id, fingerprint],
                    },
                }
            )
            fix = data.get("fix")
            if isinstance(fix, Mapping):
                edits = _list(fix.get("edits"))
                lsp_edits = []
                for edit in edits:
                    if not isinstance(edit, Mapping):
                        continue
                    replacement = str(edit.get("replacement") or edit.get("newText") or "")
                    lsp_edits.append(
                        {
                            "range": diagnostic["range"],
                            "newText": replacement,
                        }
                    )
                if lsp_edits:
                    actions.append(
                        {
                            "title": f"CommitGuard: apply safe fix for {rule_id}",
                            "kind": "quickfix",
                            "diagnostics": [diagnostic],
                            "edit": {"changes": {uri: lsp_edits}},
                        }
                    )
        return actions

    def handle(
        self, message: Mapping[str, Any], stdout: BinaryIO
    ) -> dict[str, Any] | None:
        method = str(message.get("method") or "")
        request_id = message.get("id")
        params = _mapping(message.get("params"))

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "capabilities": {
                        "textDocumentSync": {
                            "openClose": True,
                            "change": 1,
                            "save": {"includeText": True},
                        },
                        "codeActionProvider": True,
                        "executeCommandProvider": {
                            "commands": ["commitguard.explain"]
                        },
                    },
                    "serverInfo": {"name": "commitguard-lsp", "version": "1"},
                },
            }
        if method == "initialized":
            return None
        if method == "shutdown":
            self.shutdown_requested = True
            return {"jsonrpc": "2.0", "id": request_id, "result": None}
        if method == "exit":
            return None
        if method == "textDocument/didOpen":
            document = _mapping(params.get("textDocument"))
            uri = str(document.get("uri") or "")
            text = str(document.get("text") or "")
            if uri:
                self.documents[uri] = {"text": text, "version": document.get("version")}
                self.diagnostics[uri] = self._diagnostics_for(text, uri)
                self._publish(uri, stdout)
            return None
        if method == "textDocument/didChange":
            document = _mapping(params.get("textDocument"))
            uri = str(document.get("uri") or "")
            changes = _list(params.get("contentChanges"))
            if uri and changes:
                last = _mapping(changes[-1])
                text = str(last.get("text") or "")
                self.documents[uri] = {"text": text, "version": document.get("version")}
                self.diagnostics[uri] = self._diagnostics_for(text, uri)
                self._publish(uri, stdout)
            return None
        if method == "textDocument/didSave":
            uri = str(_mapping(params.get("textDocument")).get("uri") or "")
            raw_text = params.get("text")
            if uri:
                text = (
                    raw_text
                    if isinstance(raw_text, str)
                    else str(self.documents.get(uri, {}).get("text") or "")
                )
                self.diagnostics[uri] = self._diagnostics_for(text, uri)
                self._publish(uri, stdout)
            return None
        if method == "textDocument/didClose":
            uri = str(_mapping(params.get("textDocument")).get("uri") or "")
            if uri:
                self.documents.pop(uri, None)
                self.diagnostics.pop(uri, None)
                write_message(
                    stdout,
                    {
                        "jsonrpc": "2.0",
                        "method": "textDocument/publishDiagnostics",
                        "params": {"uri": uri, "diagnostics": []},
                    },
                )
            return None
        if method == "textDocument/codeAction":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": self._code_actions(params),
            }
        if method == "workspace/executeCommand":
            command = str(params.get("command") or "")
            if command == "commitguard.explain":
                arguments = _list(params.get("arguments"))
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "rule_id": arguments[0] if arguments else "",
                        "fingerprint": arguments[1] if len(arguments) > 1 else "",
                    },
                }
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unknown command: {command}"},
            }
        if request_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
        return None

    def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> int:
        while True:
            try:
                message = read_message(stdin)
            except LSPError as exc:
                write_message(
                    stdout,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": str(exc)},
                    },
                )
                continue
            if message is None:
                return 0
            if message.get("method") == "exit":
                return 0
            response = self.handle(message, stdout)
            if response is not None:
                write_message(stdout, response)
            if self.shutdown_requested and message.get("method") != "exit":
                continue


def serve_stdio(repo_root: str | Path = ".", stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    server = LanguageServer(Path(repo_root))
    return server.serve(stdin or sys.stdin.buffer, stdout or sys.stdout.buffer)
