"""Python AST taint engine wrapper, preserving legacy suppression behaviour."""

from __future__ import annotations

import time
from dataclasses import replace

from core.ast_taint import scan_python_taint
from core.engines.base import EngineCapability, EngineResult, ScanContext
from core.paths import PathMatcher
from core.scanner import is_inline_suppressed


class TaintEngine:
    name = "ast"

    def capability(self) -> EngineCapability:
        return EngineCapability(
            name=self.name,
            languages=frozenset({"python"}),
            categories=frozenset({"sast"}),
            supports_flows=True,
            version="1",
        )

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    def run(self, context: ScanContext) -> EngineResult:
        started = time.perf_counter()
        if not context.python_paths:
            return EngineResult(engine=self.name)
        changed_lines: dict[str, set[int]] = {}
        for diff_line in context.diff_lines:
            changed_lines.setdefault(diff_line.file_path, set()).add(
                diff_line.line_number
            )
        result = scan_python_taint(context.files or {}, changed_lines)
        excluded = PathMatcher(context.path_excludes)
        findings = []
        for match in result.matches:
            finding = match.finding
            lines = (context.files or {}).get(finding.file, [])
            changed = changed_lines.get(finding.file, set())
            if (
                finding.file in context.ignored_files
                or finding.rule_id in context.ignored_rule_ids
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
            warnings=result.warnings,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine=self.name,
        )
