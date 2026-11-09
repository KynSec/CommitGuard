"""Interprocedural taint analysis for JavaScript/TypeScript, Java, and Go.

The analyzer builds conservative per-function summaries (which parameters reach
a sink, which parameters are returned, and whether a function returns a source)
and propagates taint across same-file and cross-file calls to a fixed point.
It complements the Python AST analyzer and the line-oriented JavaScript engine.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.ast_taint import TAINT_RULES
from core.paths import PathMatcher
from core.scanner import Finding

_MAX_SOURCE_FILES = 750
_MAX_SOURCE_BYTES = 512 * 1024
_EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".commit_guard",
    ".tox",
}

_EXTENSIONS = {
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "java": (".java",),
    "go": (".go",),
}

_RESERVED = frozenset(
    {
        "catch",
        "class",
        "constructor",
        "do",
        "else",
        "finally",
        "for",
        "function",
        "if",
        "new",
        "return",
        "switch",
        "synchronized",
        "throw",
        "try",
        "while",
    }
)
_JAVA_PARAM_NOISE = frozenset({"final", "var", "val", "const"})

_JS_SOURCE_RE = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:query|body|params|headers|cookies|url|files)\b"
    r"|\b(?:window|document)\s*\.\s*location\b"
    r"|\blocation\s*\.\s*(?:search|hash|href)\b"
    r"|\bprocess\s*\.\s*argv\b"
    r"|\b(?:event|e)\s*\.\s*(?:target|currentTarget)\b"
    r"|\bURLSearchParams\b"
)
_JAVA_SOURCE_RE = re.compile(
    r"\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getInputStream|getReader|getQueryString|getCookies|getPathInfo)\s*\("
    r"|\bSystem\s*\.\s*(?:getenv|getProperty)\s*\("
    r"|\bargs\s*\["
    r"|@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b"
    r"|\bgetParameter\s*\("
)
_GO_SOURCE_RE = re.compile(
    r"\b(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query|FormValue|PostFormValue|Header\s*\.\s*Get|Body)\b"
    r"|\bos\s*\.\s*(?:Args|Getenv)\b"
    r"|\bflag\s*\.\s*Arg\b"
    r"|\bc\s*\.\s*(?:Param|Query|PostForm|FormValue)\b"
    r"|\bctx\s*\.\s*(?:Request|Value)\b"
)

_JS_SINKS = (
    (re.compile(r"\b(?:eval|Function)\s*\("), "cg-js-ast-code-exec-taint"),
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
    (re.compile(r"\b(?:fetch|axios(?:\.\w+)?)\s*\("), "cg-js-ast-ssrf-taint"),
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

_JAVA_SINKS = (
    (
        re.compile(
            r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
            r"|\bProcessBuilder\s*\(|\bScriptEngine\b.*\beval\s*\("
        ),
        "cg-java-ast-code-exec-taint",
    ),
    (
        re.compile(
            r"\b(?:executeQuery|executeUpdate|executeLargeUpdate|execute)\s*\("
            r"|\b(?:JdbcTemplate|NamedParameterJdbcTemplate)\b.*\b(?:query|update|execute)\s*\("
        ),
        "cg-java-ast-sqli-taint",
    ),
    (
        re.compile(r"\bRuntime\b.*\bexec\s*\(|\bProcessBuilder\s*\("),
        "cg-java-ast-shell-taint",
    ),
    (
        re.compile(
            r"\bnew\s+URL\s*\(|\bopenConnection\s*\("
            r"|\b(?:HttpClient|RestTemplate|WebClient|HttpURLConnection)\b"
        ),
        "cg-java-ast-ssrf-taint",
    ),
    (
        re.compile(
            r"\bnew\s+File\s*\(|\bPaths\s*\.\s*get\s*\("
            r"|\bFiles\s*\.\s*(?:read|write|newInputStream|newOutputStream|delete)\w*\s*\("
            r"|\bnew\s+File(?:Input|Output)Stream\s*\("
        ),
        "cg-java-ast-path-traversal-taint",
    ),
    (
        re.compile(
            r"\bgetWriter\s*\(\s*\)\s*\.\s*(?:write|print|println)\s*\("
            r"|\bout\s*\.\s*(?:print|println)\s*\("
            r"|\bresponse\s*\.\s*getWriter\b"
        ),
        "cg-java-ast-xss-taint",
    ),
)

_GO_SINKS = (
    (
        re.compile(r"\bexec\s*\.\s*Command\s*\(\s*\"sh\"|\bplugin\s*\.\s*Open\s*\("),
        "cg-go-ast-code-exec-taint",
    ),
    (
        re.compile(
            r"\b(?:db|tx|conn|sqlDB)\s*\.\s*"
            r"(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\("
        ),
        "cg-go-ast-sqli-taint",
    ),
    (re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\("), "cg-go-ast-shell-taint"),
    (
        re.compile(
            r"\bhttp\s*\.\s*(?:Get|Post|NewRequest|NewRequestWithContext)\s*\("
            r"|\bclient\s*\.\s*(?:Get|Post|Do)\s*\("
        ),
        "cg-go-ast-ssrf-taint",
    ),
    (
        re.compile(
            r"\bos\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Remove|Create)\s*\("
            r"|\bioutil\s*\.\s*(?:ReadFile|WriteFile)\s*\("
        ),
        "cg-go-ast-path-traversal-taint",
    ),
    (
        re.compile(
            r"\bfmt\s*\.\s*Fprintf\s*\(\s*w\b|\bw\s*\.\s*Write\s*\("
            r"|\btemplate\s*\.\s*HTML\s*\("
        ),
        "cg-go-ast-xss-taint",
    ),
)

_JS_FUNCTION_PATTERNS = (
    (re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{"), "brace"),
    (
        re.compile(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
            r"\(([^)]*)\)\s*=>"
        ),
        "arrow",
    ),
    (
        re.compile(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
            r"([A-Za-z_$][\w$]*)\s*=>"
        ),
        "arrow_single",
    ),
    (re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{"), "brace"),
)
_JAVA_FUNCTION_PATTERNS = (
    (
        re.compile(
            r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default|strictfp)\s+)*"
            r"(?:<[^>]+>\s+)?"
            r"(?:[\w.$]+(?:\s*<[^;{}()]*>)?(?:\s*\[\s*\])*\s+)?"
            r"([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
            r"(?:throws\s+[\w,.\s]+)?\{"
        ),
        "brace",
    ),
    (
        re.compile(
            r"\b(?:public|private|protected|static|final|synchronized|abstract|native|default|strictfp)"
            r"(?:\s+[\w<>\[\],.?\s]+)?\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
            r"(?:throws\s+[\w,.\s]+)?\{"
        ),
        "brace",
    ),
    (
        re.compile(
            r"\b(?:public|private|protected)\s+([A-Z]\w*)\s*\(([^)]*)\)\s*"
            r"(?:throws\s+[\w,.\s]+)?\{"
        ),
        "brace",
    ),
)
_GO_FUNCTION_PATTERNS = (
    (
        re.compile(
            r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
            r"(?:\([^)]*\)|[\w\[\]*.]+)?\s*\{"
        ),
        "brace",
    ),
)

_ASSIGN_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*(.*)"
)
_AUGMENTED_ASSIGN_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\+=\s*(.*)")
_GO_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*:=\s*(.*)")
_RETURN_RE = re.compile(r"^\s*return\b\s*(.*?);?\s*$")
_CALL_RE = re.compile(
    r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\("
)


@dataclass(frozen=True)
class TaintToken:
    kind: str
    index: int
    file: str


@dataclass(frozen=True)
class InterproceduralMatch:
    finding: Finding
    sink_line: int


@dataclass(frozen=True)
class InterproceduralResult:
    matches: tuple[InterproceduralMatch, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionDef:
    file: str
    language: str
    name: str
    params: tuple[str, ...]
    start: int
    end: int
    body: tuple[tuple[int, str], ...]


@dataclass
class FunctionSummary:
    sink_params: dict[int, tuple[str, int]] = field(default_factory=dict)
    return_params: set[int] = field(default_factory=set)
    returns_source: bool = False

    def merge(self, other: FunctionSummary) -> FunctionSummary:
        sinks = dict(self.sink_params)
        for index, sink in other.sink_params.items():
            sinks.setdefault(index, sink)
        return FunctionSummary(
            sink_params=sinks,
            return_params=self.return_params | other.return_params,
            returns_source=self.returns_source or other.returns_source,
        )

    def as_tuple(self) -> tuple[object, ...]:
        return (
            tuple(sorted(self.sink_params.items())),
            tuple(sorted(self.return_params)),
            self.returns_source,
        )


def language_for(path: str) -> str:
    suffix = Path(path).suffix.lower()
    for language, extensions in _EXTENSIONS.items():
        if suffix in extensions:
            return language
    return ""


def _source_re(language: str) -> re.Pattern[str]:
    if language == "javascript":
        return _JS_SOURCE_RE
    if language == "java":
        return _JAVA_SOURCE_RE
    return _GO_SOURCE_RE


def _sinks(language: str) -> tuple[tuple[re.Pattern[str], str], ...]:
    if language == "javascript":
        return _JS_SINKS
    if language == "java":
        return _JAVA_SINKS
    return _GO_SINKS


def _function_patterns(language: str) -> tuple[tuple[re.Pattern[str], str], ...]:
    if language == "javascript":
        return _JS_FUNCTION_PATTERNS
    if language == "java":
        return _JAVA_FUNCTION_PATTERNS
    return _GO_FUNCTION_PATTERNS


def _split_top_level(raw: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _param_names(raw: str, language: str) -> tuple[str, ...]:
    names: list[str] = []
    for part in _split_top_level(raw):
        if not part:
            continue
        if language == "javascript":
            if part.startswith(("{", "[")):
                names.extend(re.findall(r"[A-Za-z_$][\w$]*", part))
                continue
            candidate = part.split("=", 1)[0].split(":", 1)[0].strip()
            match = re.search(r"([A-Za-z_$][\w$]*)\s*$", candidate)
            if match:
                names.append(match.group(1))
        elif language == "java":
            tokens = [
                token
                for token in re.findall(r"[A-Za-z_]\w*", part)
                if token not in _JAVA_PARAM_NOISE
            ]
            if tokens:
                names.append(tokens[-1])
        else:
            tokens = re.findall(r"[A-Za-z_]\w*", part.replace("...", " "))
            if tokens and tokens[0] != "_":
                names.append(tokens[0])
    return tuple(
        name for name in names if name and name not in _RESERVED and name != "_"
    )


def _match_braces(lines: list[str], start_line: int, start_col: int) -> int:
    depth = 0
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    for line_index in range(start_line, len(lines)):
        text = lines[line_index]
        col = start_col if line_index == start_line else 0
        while col < len(text):
            char = text[col]
            nxt = text[col + 1] if col + 1 < len(text) else ""
            if in_line_comment:
                break
            if in_block_comment:
                if char == "*" and nxt == "/":
                    in_block_comment = False
                    col += 2
                    continue
                col += 1
                continue
            if in_string:
                if char == "\\":
                    col += 2
                    continue
                if char == in_string:
                    in_string = None
                col += 1
                continue
            if char in "\"'`":
                in_string = char
                col += 1
                continue
            if char == "/" and nxt == "/":
                in_line_comment = True
                break
            if char == "/" and nxt == "*":
                in_block_comment = True
                col += 2
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return line_index
            col += 1
        in_line_comment = False
    return len(lines) - 1


def _expression_end(lines: list[str], start_line: int, start_col: int) -> int:
    for line_index in range(start_line, min(start_line + 40, len(lines))):
        text = lines[line_index]
        col = start_col if line_index == start_line else 0
        if text.find(";", col) != -1:
            return line_index
    return start_line


def _parse_functions(path: str, lines: list[str], language: str) -> list[FunctionDef]:
    functions: list[FunctionDef] = []
    for line_index, text in enumerate(lines):
        for pattern, kind in _function_patterns(language):
            match = pattern.search(text)
            if not match:
                continue
            name = match.group(1)
            if name in _RESERVED:
                continue
            raw_params = match.group(2)
            if kind == "brace":
                brace_col = text.find("{", match.start())
                if brace_col == -1:
                    continue
                end_line = _match_braces(lines, line_index, brace_col)
            else:
                arrow = text.find("=>", match.start())
                if arrow == -1:
                    continue
                body_col = arrow + 2
                while body_col < len(text) and text[body_col].isspace():
                    body_col += 1
                if kind == "arrow" and body_col < len(text) and text[body_col] == "{":
                    end_line = _match_braces(lines, line_index, body_col)
                else:
                    end_line = _expression_end(lines, line_index, body_col)
            body = tuple(
                (number, lines[number - 1])
                for number in range(line_index + 1, end_line + 2)
            )
            functions.append(
                FunctionDef(
                    file=path,
                    language=language,
                    name=name,
                    params=_param_names(raw_params, language),
                    start=line_index + 1,
                    end=end_line + 1,
                    body=body,
                )
            )
            break
    return functions


def _identifier_used(text: str, name: str) -> bool:
    return (
        re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text) is not None
    )


def _assignment(text: str, language: str) -> tuple[str, str] | None:
    if language == "go":
        match = _GO_ASSIGN_RE.search(text)
        if match:
            return match.group(1), match.group(2)
    for pattern in (_AUGMENTED_ASSIGN_RE, _ASSIGN_RE):
        match = pattern.search(text)
        if match:
            name = match.group(1)
            if name in _RESERVED:
                continue
            return name, match.group(2)
    return None


def _balanced_parens(text: str, open_index: int) -> tuple[str | None, int]:
    depth = 0
    in_string: str | None = None
    index = open_index
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == in_string:
                in_string = None
            index += 1
            continue
        if char in "\"'`":
            in_string = char
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index], index
        index += 1
    return None, -1


def _iter_calls(text: str) -> list[tuple[str, tuple[str, ...]]]:
    calls: list[tuple[str, tuple[str, ...]]] = []
    for match in _CALL_RE.finditer(text):
        callee = match.group(1).replace(" ", "")
        last = callee.split(".")[-1]
        if last in _RESERVED:
            continue
        args_text, _close = _balanced_parens(text, match.end() - 1)
        if args_text is None:
            continue
        calls.append((last, tuple(_split_top_level(args_text))))
    return calls


def _resolve_callee(
    name: str, function: FunctionDef, by_name: dict[str, list[FunctionDef]]
) -> list[FunctionDef]:
    candidates = by_name.get(name, [])
    if not candidates:
        return []
    same_file = [item for item in candidates if item.file == function.file]
    if same_file:
        return same_file
    same_dir = [
        item
        for item in candidates
        if Path(item.file).parent == Path(function.file).parent
    ]
    if same_dir:
        return same_dir
    return candidates


def _tokens_in(
    expression: str,
    tainted: dict[str, set[TaintToken]],
    source_re: re.Pattern[str],
    file: str,
    line: int,
) -> set[TaintToken]:
    tokens: set[TaintToken] = set()
    if source_re.search(expression):
        tokens.add(TaintToken("source", line, file))
    for name, variable_tokens in tainted.items():
        if _identifier_used(expression, name):
            tokens |= variable_tokens
    return tokens


def _make_finding(
    function: FunctionDef,
    line: int,
    rule_id: str,
    text: str,
    source: TaintToken,
) -> Finding:
    details = TAINT_RULES[rule_id]
    flagged = text.strip()
    if not flagged:
        flagged = f"{function.name}(...)"
    fingerprint = hashlib.sha256(
        f"{rule_id}\0{function.file}\0{line}\0{flagged}".encode(
            "utf-8", "replace"
        )
    ).hexdigest()[:16]
    location = (
        f"{source.file}:{source.index}"
        if source.file != function.file
        else f"line {source.index}"
    )
    description = (
        f"{details['description']} (sink at line {line}; "
        f"tainted source at {location})."
    )
    return Finding(
        file=function.file,
        line_number=line,
        rule_id=rule_id,
        description=description,
        severity=str(details["severity"]),
        source=f"{function.language}_ast",
        flagged_code=flagged[:500],
        redacted_code=flagged[:500],
        fingerprint=fingerprint,
        tags=tuple(details["tags"]),
        cwe=str(details["cwe"]),
    )


def _analyze_function(
    function: FunctionDef,
    summaries: dict[int, FunctionSummary],
    by_name: dict[str, list[FunctionDef]],
) -> tuple[list[Finding], FunctionSummary]:
    summary = FunctionSummary()
    tainted: dict[str, set[TaintToken]] = {
        name: {TaintToken("param", index, function.file)}
        for index, name in enumerate(function.params)
    }
    findings: list[Finding] = []
    source_re = _source_re(function.language)
    for line, text in function.body:
        line_tokens: set[TaintToken] = set()
        if source_re.search(text):
            line_tokens.add(TaintToken("source", line, function.file))
        for name, tokens in tainted.items():
            if _identifier_used(text, name):
                line_tokens |= tokens

        assignment = _assignment(text, function.language)
        if assignment:
            target, rhs = assignment
            rhs_tokens = _tokens_in(rhs, tainted, source_re, function.file, line)
            if rhs_tokens:
                tainted[target] = rhs_tokens
            else:
                tainted.pop(target, None)

        for pattern, rule_id in _sinks(function.language):
            if pattern.search(text) and line_tokens:
                for token in line_tokens:
                    if token.kind == "source":
                        findings.append(
                            _make_finding(function, line, rule_id, text, token)
                        )
                for token in line_tokens:
                    if token.kind == "param":
                        summary.sink_params.setdefault(
                            token.index, (rule_id, line)
                        )
                break

        for callee_name, args in _iter_calls(text):
            candidates = _resolve_callee(callee_name, function, by_name)
            if not candidates:
                continue
            callee_summary = summaries.get(id(candidates[0]))
            if callee_summary is None:
                continue
            argument_tokens = [
                _tokens_in(arg, tainted, source_re, function.file, line)
                for arg in args
            ]
            for index, (rule_id, _sink_line) in callee_summary.sink_params.items():
                if index >= len(argument_tokens):
                    continue
                for token in argument_tokens[index]:
                    if token.kind == "source":
                        findings.append(
                            _make_finding(function, line, rule_id, text, token)
                        )
                    else:
                        summary.sink_params.setdefault(token.index, (rule_id, line))
            if assignment:
                target, _rhs = assignment
                propagated: set[TaintToken] = set()
                if callee_summary.returns_source:
                    propagated.add(TaintToken("source", line, function.file))
                for index in callee_summary.return_params:
                    if index < len(argument_tokens):
                        propagated |= argument_tokens[index]
                if propagated:
                    tainted[target] = tainted.get(target, set()) | propagated

        returned = _RETURN_RE.match(text)
        if returned:
            expression = returned.group(1)
            for name, tokens in tainted.items():
                if not _identifier_used(expression, name):
                    continue
                for token in tokens:
                    if token.kind == "param":
                        summary.return_params.add(token.index)
                    else:
                        summary.returns_source = True
            if source_re.search(expression):
                summary.returns_source = True
    return findings, summary


def _discover_sources(
    repo_root: Path,
    known: dict[str, list[str]],
    languages: set[str],
    includes: tuple[str, ...],
    excludes: tuple[str, ...],
) -> dict[str, list[str]]:
    sources: dict[str, list[str]] = {}
    extensions: set[str] = set()
    for language in languages:
        extensions.update(_EXTENSIONS.get(language, ()))
    if not extensions:
        return sources
    include_matcher = PathMatcher(includes) if includes else None
    exclude_matcher = PathMatcher(excludes) if excludes else None
    seen = 0
    try:
        walker = os.walk(repo_root)
        for dirpath, dirnames, filenames in walker:
            dirnames[:] = [
                name for name in dirnames if name not in _EXCLUDED_DIRECTORIES
            ]
            for filename in filenames:
                if seen >= _MAX_SOURCE_FILES:
                    return sources
                if Path(filename).suffix.lower() not in extensions:
                    continue
                candidate = Path(dirpath) / filename
                try:
                    relative = candidate.relative_to(repo_root).as_posix()
                except ValueError:
                    continue
                if relative in known:
                    continue
                if include_matcher is not None and not include_matcher.matches(
                    relative
                ):
                    continue
                if exclude_matcher is not None and exclude_matcher.matches(relative):
                    continue
                try:
                    if candidate.stat().st_size > _MAX_SOURCE_BYTES:
                        continue
                    sources[relative] = candidate.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                except OSError:
                    continue
                seen += 1
    except OSError:
        return sources
    return sources


def scan_interprocedural(
    files: dict[str, list[str]],
    changed_lines: dict[str, set[int]],
    *,
    repo_root: Path | None = None,
    includes: tuple[str, ...] = (),
    excludes: tuple[str, ...] = (),
) -> InterproceduralResult:
    """Scans JavaScript/TypeScript, Java, and Go files for interprocedural flows."""
    languages = {
        language_for(path)
        for path in changed_lines
        if language_for(path)
    }
    if not languages:
        return InterproceduralResult()
    analysis_files = dict(files or {})
    if repo_root is not None:
        for path, lines in _discover_sources(
            Path(repo_root), analysis_files, languages, includes, excludes
        ).items():
            analysis_files.setdefault(path, lines)

    functions: list[FunctionDef] = []
    warnings: list[str] = []
    for path in sorted(changed_lines):
        if path not in analysis_files:
            warnings.append(f"{path}: source content was unavailable")
    for path, lines in analysis_files.items():
        language = language_for(path)
        if language not in languages:
            continue
        if not lines:
            warnings.append(f"{path}: source content was unavailable")
            continue
        functions.extend(_parse_functions(path, lines, language))

    by_name: dict[str, list[FunctionDef]] = {}
    for function in functions:
        by_name.setdefault(function.name, []).append(function)
    summaries: dict[int, FunctionSummary] = {
        id(function): FunctionSummary() for function in functions
    }

    collected: dict[tuple[str, int, str], Finding] = {}
    for _iteration in range(5):
        changed = False
        for function in functions:
            findings, summary = _analyze_function(function, summaries, by_name)
            for finding in findings:
                key = (finding.file, finding.line_number, finding.rule_id)
                collected.setdefault(key, finding)
            current = summaries[id(function)]
            merged = current.merge(summary)
            if merged.as_tuple() != current.as_tuple():
                summaries[id(function)] = merged
                changed = True
        if not changed:
            break

    matches = [
        InterproceduralMatch(finding, finding.line_number)
        for finding in collected.values()
        if finding.file in changed_lines
    ]
    return InterproceduralResult(tuple(matches), tuple(warnings))
