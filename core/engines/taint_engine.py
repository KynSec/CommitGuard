"""Python and JavaScript/TypeScript taint engine wrapper."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

from core.ast_taint import scan_js_taint, scan_python_taint
from core.engines.base import EngineCapability, EngineResult, ScanContext
from core.paths import PathMatcher
from core.scanner import is_inline_suppressed

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
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_SOURCE_FILES = 750


def _needs_cross_file(
    files: dict[str, list[str]], python_lines: dict[str, set[int]]
) -> bool:
    for path in python_lines:
        for line in files.get(path, ())[:200]:
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                return True
    return False


def _discover_python_sources(
    repo_root: Path,
    known: dict[str, list[str]],
    includes: tuple[str, ...] = (),
    excludes: tuple[str, ...] = (),
) -> dict[str, list[str]]:
    """Loads repository Python files for cross-file summaries, within caps."""
    sources: dict[str, list[str]] = {}
    root = Path(repo_root)
    if not root.is_dir():
        return sources
    include_matcher = PathMatcher(includes) if includes else None
    exclude_matcher = PathMatcher(excludes) if excludes else None
    try:
        candidates = root.rglob("*.py")
    except OSError:
        return sources
    seen = 0
    for candidate in candidates:
        if seen >= _MAX_SOURCE_FILES:
            break
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:
            continue
        if relative in known or any(
            part in _EXCLUDED_DIRECTORIES for part in Path(relative).parts
        ):
            continue
        if include_matcher is not None and not include_matcher.matches(relative):
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
    return sources


class TaintEngine:
    name = "ast"

    def capability(self) -> EngineCapability:
        return EngineCapability(
            name=self.name,
            languages=frozenset({"python", "javascript", "typescript"}),
            categories=frozenset({"sast"}),
            supports_flows=True,
            version="1",
        )

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    def run(self, context: ScanContext) -> EngineResult:
        started = time.perf_counter()
        if not context.changed_paths:
            return EngineResult(engine=self.name)
        changed_lines: dict[str, set[int]] = {}
        for diff_line in context.diff_lines:
            changed_lines.setdefault(diff_line.file_path, set()).add(
                diff_line.line_number
            )
        python_lines = {
            path: lines
            for path, lines in changed_lines.items()
            if path.lower().endswith((".py", ".pyi"))
        }
        js_lines = {
            path: lines
            for path, lines in changed_lines.items()
            if path.lower().endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"))
        }
        analysis_files = dict(context.files or {})
        if python_lines and _needs_cross_file(analysis_files, python_lines):
            for path, lines in _discover_python_sources(
                context.repo_root,
                analysis_files,
                context.path_includes,
                context.path_excludes,
            ).items():
                analysis_files.setdefault(path, lines)
        python_result = scan_python_taint(analysis_files, python_lines)
        js_result = scan_js_taint(context.files or {}, js_lines)
        matches = (*python_result.matches, *js_result.matches)
        warnings = (*python_result.warnings, *js_result.warnings)
        excluded = PathMatcher(context.path_excludes)
        findings = []
        for match in matches:
            finding = match.finding
            lines = (context.files or {}).get(finding.file, [])
            changed = changed_lines.get(finding.file, set())
            if (
                finding.file in context.ignored_files
                or finding.rule_id in context.ignored_rule_ids
                or (
                    context.enabled_rule_ids is not None
                    and finding.rule_id not in context.enabled_rule_ids
                )
                or excluded.matches(finding.file)
                or any(
                    pattern.search(finding.file)
                    for pattern in context.path_allowlist
                )
            ):
                continue
            if is_inline_suppressed(
                lines,
                finding.line_number,
                finding.rule_id,
                changed_lines=changed,
                ignore_inline=context.ignore_inline,
            ) or is_inline_suppressed(
                lines,
                match.sink_line,
                finding.rule_id,
                changed_lines=changed,
                ignore_inline=context.ignore_inline,
            ):
                continue
            flows = []
            if match.sink_line and match.sink_line != finding.line_number:
                flows.append(
                    {
                        "file": finding.file,
                        "line": finding.line_number,
                        "message": "tainted source",
                    }
                )
                flows.append(
                    {
                        "file": finding.file,
                        "line": match.sink_line,
                        "message": "dangerous sink",
                    }
                )
            findings.append(
                replace(
                    finding,
                    engine=self.name,
                    category="sast",
                    confidence="high",
                    severity=context.severity_overrides.get(
                        finding.rule_id, finding.severity
                    ),
                    code_flows=tuple(flows),
                )
            )
        return EngineResult(
            findings=tuple(findings),
            warnings=warnings,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine=self.name,
        )
