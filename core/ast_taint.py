"""Conservative, intraprocedural Python AST taint checks."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass

from core.scanner import Finding

TAINT_RULES = {
    "cg-python-ast-sqli-taint": {
        "description": "Request-controlled data reaches a SQL execute() query; use query parameters.",
        "severity": "high",
        "cwe": "CWE-89",
        "tags": ("sqli", "injection", "taint", "ast"),
    },
    "cg-python-ast-shell-taint": {
        "description": "Request-controlled data reaches a shell command; avoid shell execution or validate arguments.",
        "severity": "high",
        "cwe": "CWE-78",
        "tags": ("command-injection", "taint", "ast"),
    },
    "cg-python-ast-ssrf-taint": {
        "description": "Request-controlled data reaches an outbound network request; validate or allowlist destination URLs (SSRF).",
        "severity": "high",
        "cwe": "CWE-918",
        "tags": ("ssrf", "web", "taint", "ast"),
    },
    "cg-python-ast-path-traversal-taint": {
        "description": "Request-controlled data reaches a filesystem API without visible boundary validation.",
        "severity": "high",
        "cwe": "CWE-22",
        "tags": ("path-traversal", "web", "taint", "ast"),
    },
    "cg-python-ast-xss-taint": {
        "description": "Request-controlled data is rendered directly into HTML or unescaped template string (XSS/SSTI).",
        "severity": "high",
        "cwe": "CWE-79",
        "tags": ("xss", "ssti", "web", "taint", "ast"),
    },
    "cg-python-ast-llm-code-exec-taint": {
        "description": "Untrusted or LLM-generated output reaches an exec() or eval() call; avoid dynamic code execution.",
        "severity": "critical",
        "cwe": "CWE-95",
        "tags": ("ai", "llm", "rce", "taint", "ast"),
    },
}

_REQUEST_INPUTS = {
    "args",
    "form",
    "values",
    "json",
    "data",
    "headers",
    "cookies",
    "FILES",
    "GET",
    "POST",
    "META",
    "path_params",
    "view_args",
    "query_params",
    "params",
    "body",
}
_LLM_OUTPUT_ATTRS = {"content", "text", "choices", "output", "response"}
_LLM_CLIENT_CALLS = {"invoke", "predict", "generate_content", "create", "complete"}
_SUBPROCESS_FUNCTIONS = {
    "run",
    "call",
    "Popen",
    "check_call",
    "check_output",
}


@dataclass(frozen=True)
class TaintMatch:
    finding: Finding
    sink_line: int


@dataclass(frozen=True)
class TaintResult:
    matches: tuple[TaintMatch, ...] = ()
    warnings: tuple[str, ...] = ()


def _attribute_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return list(reversed(parts))


def _is_request_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        chain = _attribute_chain(node)
        if (
            len(chain) >= 2
            and chain[0] in {"request", "req"}
            and any(part in _REQUEST_INPUTS for part in chain[1:])
        ):
            return True
        if (
            len(chain) >= 2
            and chain[0] in {"response", "completion", "result", "llm_output", "ai_response"}
            and any(part in _LLM_OUTPUT_ATTRS for part in chain[1:])
        ):
            return True
    if isinstance(node, ast.Call):
        function = node.func
        if (
            isinstance(function, ast.Name)
            and function.id == "input"
        ) or (
            isinstance(function, ast.Attribute)
            and _attribute_chain(function) == ["builtins", "input"]
        ):
            return True
        if isinstance(function, ast.Attribute):
            chain = _attribute_chain(function)
            if any(call_name in chain[-1:] for call_name in _LLM_CLIENT_CALLS) and any(
                mod in chain
                for mod in ("llm", "model", "chat", "client", "openai", "anthropic")
            ):
                return True
    return False


def _is_tainted(node: ast.AST, tainted: dict[str, set[int]]) -> set[int]:
    if _is_request_source(node):
        return {getattr(node, "lineno", 1)}
    if isinstance(node, ast.Name):
        return set(tainted.get(node.id, ()))
    sources: set[int] = set()
    for child in ast.iter_child_nodes(node):
        sources.update(_is_tainted(child, tainted))
    return sources


def _call_argument(call: ast.Call, keyword_names: set[str]) -> ast.AST | None:
    if call.args:
        return call.args[0]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg in keyword_names),
        None,
    )


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in target.elts))
    return set()


def _merge_states(*states: dict[str, set[int]]) -> dict[str, set[int]]:
    merged: dict[str, set[int]] = {}
    for state in states:
        for name, sources in state.items():
            merged.setdefault(name, set()).update(sources)
    return merged


class _TaintAnalyzer:
    def __init__(self, path: str, lines: list[str], changed: set[int]) -> None:
        self.path = path
        self.lines = lines
        self.changed = changed
        self.matches: dict[tuple[str, int], TaintMatch] = {}

    def _record(
        self,
        call: ast.Call,
        rule_id: str,
        sources: set[int],
    ) -> None:
        if not sources:
            return
        sink_line = getattr(call, "lineno", 1)
        sink_end = getattr(call, "end_lineno", sink_line)
        changed_sink_lines = sorted(
            line for line in self.changed if sink_line <= line <= sink_end
        )
        changed_source_lines = sorted(sources & self.changed)
        if not changed_sink_lines and not changed_source_lines:
            return

        finding_line = (
            changed_sink_lines[0]
            if changed_sink_lines
            else changed_source_lines[-1]
        )
        if not 1 <= finding_line <= len(self.lines):
            return
        flagged = self.lines[finding_line - 1].strip()
        if not flagged:
            return
        details = TAINT_RULES[rule_id]
        description = (
            f"{details['description']} (sink at line {sink_line}; "
            f"tainted source at line {min(sources)})."
        )
        fingerprint = hashlib.sha256(
            f"{rule_id}\0{self.path}\0{sink_line}\0{flagged}".encode(
                "utf-8", "replace"
            )
        ).hexdigest()[:16]
        match = TaintMatch(
            Finding(
                file=self.path,
                line_number=finding_line,
                rule_id=rule_id,
                description=description,
                severity=str(details["severity"]),
                source="python_ast",
                flagged_code=flagged,
                redacted_code=flagged,
                fingerprint=fingerprint,
                tags=tuple(details["tags"]),
                cwe=str(details["cwe"]),
            ),
            sink_line,
        )
        self.matches[(rule_id, sink_line)] = match

    def _check_expression(self, node: ast.AST, tainted: dict[str, set[int]]) -> None:
        for candidate in ast.walk(node):
            if not isinstance(candidate, ast.Call):
                continue
            sources = self._sink_sources(candidate, tainted)
            if sources:
                rule_id, taint = sources
                self._record(candidate, rule_id, taint)

    def _sink_sources(
        self, call: ast.Call, tainted: dict[str, set[int]]
    ) -> tuple[str, set[int]] | None:
        function = call.func
        chain = _attribute_chain(function) if isinstance(
            function, (ast.Attribute, ast.Name)
        ) else []

        if isinstance(function, ast.Attribute) and function.attr in {
            "execute",
            "executemany",
        }:
            query = _call_argument(call, {"sql", "query"})
            sources = _is_tainted(query, tainted) if query is not None else set()
            return ("cg-python-ast-sqli-taint", sources) if sources else None

        is_os_shell = (
            isinstance(function, ast.Attribute)
            and chain in (["os", "system"], ["os", "popen"])
        )
        is_subprocess = (
            isinstance(function, ast.Attribute)
            and len(chain) == 2
            and chain[0] == "subprocess"
            and chain[1] in _SUBPROCESS_FUNCTIONS
        )
        if is_os_shell:
            command = _call_argument(call, {"command"})
            sources = _is_tainted(command, tainted) if command is not None else set()
            return ("cg-python-ast-shell-taint", sources) if sources else None
        if is_subprocess and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        ):
            command = _call_argument(call, {"args"})
            sources = _is_tainted(command, tainted) if command is not None else set()
            return ("cg-python-ast-shell-taint", sources) if sources else None

        # 3. SSRF (requests, httpx, urllib, etc.)
        is_http_client = (
            isinstance(function, ast.Attribute)
            and len(chain) >= 2
            and chain[0] in {"requests", "httpx", "session", "http"}
            and chain[1] in {"get", "post", "put", "delete", "patch", "head", "request"}
        ) or (
            isinstance(function, ast.Attribute)
            and chain == ["urllib", "request", "urlopen"]
        )
        if is_http_client:
            url_arg = _call_argument(call, {"url"})
            sources = _is_tainted(url_arg, tainted) if url_arg is not None else set()
            return ("cg-python-ast-ssrf-taint", sources) if sources else None

        # 4. Path traversal (open, os.remove/unlink/rmdir/listdir, shutil...)
        is_file_open = (
            (isinstance(function, ast.Name) and function.id == "open")
            or (
                isinstance(function, ast.Attribute)
                and _attribute_chain(function) == ["builtins", "open"]
            )
            or (
                isinstance(function, ast.Attribute)
                and len(chain) == 2
                and chain[0] in {"os", "shutil"}
                and chain[1] in {
                    "remove", "unlink", "rmdir", "listdir", "open", "rmtree", "copy", "move"
                }
            )
        )
        if is_file_open:
            path_arg = _call_argument(call, {"file", "path", "filename"})
            sources = _is_tainted(path_arg, tainted) if path_arg is not None else set()
            return ("cg-python-ast-path-traversal-taint", sources) if sources else None

        # 5. XSS / Server-side Template Rendering
        is_xss_sink = (
            (
                isinstance(function, ast.Name)
                and function.id in {"render_template_string", "mark_safe", "Markup"}
            )
            or (
                isinstance(function, ast.Attribute)
                and function.attr in {"render_template_string", "mark_safe", "Markup"}
            )
        )
        if is_xss_sink:
            xss_arg = _call_argument(call, {"source", "s", "template"})
            sources = _is_tainted(xss_arg, tainted) if xss_arg is not None else set()
            return ("cg-python-ast-xss-taint", sources) if sources else None

        # 6. Dynamic Code Execution (eval / exec)
        is_code_exec = (
            (isinstance(function, ast.Name) and function.id in {"eval", "exec"})
            or (
                isinstance(function, ast.Attribute)
                and _attribute_chain(function) in (["builtins", "eval"], ["builtins", "exec"])
            )
        )
        if is_code_exec:
            code_arg = _call_argument(call, {"source", "code"})
            sources = _is_tainted(code_arg, tainted) if code_arg is not None else set()
            return ("cg-python-ast-llm-code-exec-taint", sources) if sources else None

        return None

    def _assign(self, target: ast.AST, sources: set[int], state: dict[str, set[int]]) -> None:
        for name in _target_names(target):
            if sources:
                state[name] = set(sources)
            else:
                state.pop(name, None)

    def _block(
        self, statements: list[ast.stmt], state: dict[str, set[int]]
    ) -> dict[str, set[int]]:
        current = {name: set(sources) for name, sources in state.items()}
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    if default is not None:
                        self._check_expression(default, current)
                self._block(statement.body, current.copy())
                continue
            if isinstance(statement, ast.ClassDef):
                self._block(statement.body, current.copy())
                continue
            if isinstance(statement, ast.Assign):
                self._check_expression(statement.value, current)
                sources = _is_tainted(statement.value, current)
                for target in statement.targets:
                    self._assign(target, sources, current)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    self._check_expression(statement.value, current)
                    self._assign(
                        statement.target, _is_tainted(statement.value, current), current
                    )
            elif isinstance(statement, ast.AugAssign):
                self._check_expression(statement.value, current)
                sources = _is_tainted(statement.target, current)
                sources.update(_is_tainted(statement.value, current))
                self._assign(statement.target, sources, current)
            elif isinstance(statement, ast.If):
                self._check_expression(statement.test, current)
                body = self._block(statement.body, current.copy())
                otherwise = self._block(statement.orelse, current.copy())
                current = _merge_states(body, otherwise)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self._check_expression(statement.iter, current)
                body_state = current.copy()
                self._assign(
                    statement.target, _is_tainted(statement.iter, current), body_state
                )
                body_state = self._block(statement.body, body_state)
                else_state = self._block(statement.orelse, current.copy())
                current = _merge_states(current, body_state, else_state)
            elif isinstance(statement, ast.While):
                self._check_expression(statement.test, current)
                body_state = self._block(statement.body, current.copy())
                else_state = self._block(statement.orelse, current.copy())
                current = _merge_states(current, body_state, else_state)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._check_expression(item.context_expr, current)
                    if item.optional_vars is not None:
                        self._assign(
                            item.optional_vars,
                            _is_tainted(item.context_expr, current),
                            current,
                        )
                current = self._block(statement.body, current)
            elif isinstance(statement, ast.Try):
                branches = [self._block(statement.body, current.copy())]
                branches.extend(
                    self._block(handler.body, current.copy())
                    for handler in statement.handlers
                )
                if statement.orelse:
                    branches.append(
                        self._block(statement.orelse, branches[0].copy())
                    )
                current = self._block(statement.finalbody, _merge_states(*branches))
            elif isinstance(statement, ast.Expr):
                self._check_expression(statement.value, current)
            else:
                self._check_expression(statement, current)
        return current

    def analyze(self) -> tuple[TaintMatch, ...]:
        try:
            tree = ast.parse("\n".join(self.lines), filename=self.path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            raise ValueError(f"could not parse Python syntax: {exc}") from exc
        self._block(tree.body, {})
        return tuple(self.matches.values())


def scan_python_taint(
    files: dict[str, list[str]],
    changed_lines: dict[str, set[int]],
) -> TaintResult:
    """Find changed Python flows from request/input data into SQL or shell sinks."""
    matches: list[TaintMatch] = []
    warnings: list[str] = []
    for path, changed in sorted(changed_lines.items()):
        if not path.endswith((".py", ".pyi")):
            continue
        lines = files.get(path)
        if lines is None:
            warnings.append(f"{path}: staged/current file content was unavailable")
            continue
        try:
            matches.extend(_TaintAnalyzer(path, lines, changed).analyze())
        except ValueError as exc:
            warnings.append(f"{path}: {exc}")
    return TaintResult(tuple(matches), tuple(warnings))


JS_TAINT_RULES = {
    "cg-js-ast-code-exec-taint": {
        "description": "Request or user-controlled data reaches eval/Function; avoid dynamic code execution.",
        "severity": "critical",
        "cwe": "CWE-95",
        "tags": ("ai", "rce", "taint", "javascript"),
    },
    "cg-js-ast-sqli-taint": {
        "description": "Request-controlled data reaches a database query; use parameterized queries.",
        "severity": "high",
        "cwe": "CWE-89",
        "tags": ("sqli", "injection", "taint", "javascript"),
    },
    "cg-js-ast-shell-taint": {
        "description": "Request-controlled data reaches a shell command; avoid shell execution or validate arguments.",
        "severity": "high",
        "cwe": "CWE-78",
        "tags": ("command-injection", "taint", "javascript"),
    },
    "cg-js-ast-ssrf-taint": {
        "description": "Request-controlled data reaches an outbound request URL; validate or allowlist destinations (SSRF).",
        "severity": "high",
        "cwe": "CWE-918",
        "tags": ("ssrf", "web", "taint", "javascript"),
    },
    "cg-js-ast-path-traversal-taint": {
        "description": "Request-controlled data reaches a filesystem API without visible boundary validation.",
        "severity": "high",
        "cwe": "CWE-22",
        "tags": ("path-traversal", "web", "taint", "javascript"),
    },
    "cg-js-ast-xss-taint": {
        "description": "Request-controlled data is written to HTML or a response without escaping (XSS).",
        "severity": "high",
        "cwe": "CWE-79",
        "tags": ("xss", "web", "taint", "javascript"),
    },
}

TAINT_RULES.update(JS_TAINT_RULES)

_JS_SOURCE_RE = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:query|body|params|headers|cookies|url)\b"
    r"|\b(?:window|document)\s*\.\s*location\b"
    r"|\blocation\s*\.\s*(?:search|hash|href)\b"
    r"|\bprocess\s*\.\s*argv\b"
    r"|\binput\b"
)
_JS_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*="
)
_JS_SINKS = (
    (
        re.compile(r"\b(?:eval|Function)\s*\("),
        "cg-js-ast-code-exec-taint",
    ),
    (
        re.compile(r"\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync)\s*\("),
        "cg-js-ast-shell-taint",
    ),
    (
        re.compile(
            r"\b(?:db|database|connection|pool|client|knex|sequelize)\s*\.\s*"
            r"(?:query|raw|execute|all|get|run)\s*\("
        ),
        "cg-js-ast-sqli-taint",
    ),
    (
        re.compile(r"\b(?:fetch|axios(?:\.\w+)?)\s*\("),
        "cg-js-ast-ssrf-taint",
    ),
    (
        re.compile(
            r"\b(?:fs|fsPromises|fsExtra)\s*\.\s*"
            r"(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|createReadStream|createWriteStream)\s*\("
        ),
        "cg-js-ast-path-traversal-taint",
    ),
    (
        re.compile(
            r"\.(?:innerHTML|outerHTML)\s*="
            r"|\bdocument\s*\.\s*write(?:ln)?\s*\("
            r"|\bres\s*\.\s*(?:send|write)\s*\("
        ),
        "cg-js-ast-xss-taint",
    ),
)


def _js_identifier_used(text: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def scan_js_taint(
    files: dict[str, list[str]],
    changed_lines: dict[str, set[int]],
) -> TaintResult:
    """Conservative line-oriented taint flow for JavaScript/TypeScript files."""
    matches: list[TaintMatch] = []
    warnings: list[str] = []
    for path, changed in sorted(changed_lines.items()):
        if not path.lower().endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
            continue
        lines = files.get(path)
        if lines is None:
            warnings.append(f"{path}: staged/current file content was unavailable")
            continue
        tainted: dict[str, set[int]] = {}
        for number, text in enumerate(lines, start=1):
            source_match = _JS_SOURCE_RE.search(text)
            source_lines = {number} if source_match else set()
            if source_match:
                assign = _JS_ASSIGN_RE.search(text)
                if assign:
                    tainted[assign.group(1)] = {number}
            names = {
                name
                for name, sources in tainted.items()
                if _js_identifier_used(text, {name})
            }
            for name in names:
                source_lines.update(tainted[name])
            assign = _JS_ASSIGN_RE.search(text)
            if assign and source_lines:
                tainted[assign.group(1)] = set(source_lines)
            if not source_lines:
                continue
            for pattern, rule_id in _JS_SINKS:
                if not pattern.search(text):
                    continue
                if number in changed or source_lines & changed:
                    finding_line = number if number in changed else max(source_lines & changed)
                    flagged = text.strip()
                    if not flagged:
                        continue
                    details = JS_TAINT_RULES[rule_id]
                    source_line = min(source_lines)
                    description = (
                        f"{details['description']} (sink at line {number}; "
                        f"tainted source at line {source_line})."
                    )
                    fingerprint = hashlib.sha256(
                        f"{rule_id}\0{path}\0{number}\0{flagged}".encode(
                            "utf-8", "replace"
                        )
                    ).hexdigest()[:16]
                    matches.append(
                        TaintMatch(
                            Finding(
                                file=path,
                                line_number=finding_line,
                                rule_id=rule_id,
                                description=description,
                                severity=str(details["severity"]),
                                source="javascript_ast",
                                flagged_code=flagged,
                                redacted_code=flagged,
                                fingerprint=fingerprint,
                                tags=tuple(details["tags"]),
                                cwe=str(details["cwe"]),
                            ),
                            number,
                        )
                    )
                    break
    unique: dict[tuple[str, str, int], TaintMatch] = {}
    for match in matches:
        unique[(match.finding.file, match.finding.rule_id, match.sink_line)] = match
    return TaintResult(tuple(unique.values()), tuple(warnings))
