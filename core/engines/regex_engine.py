"""Regex/native rule engine wrapper."""

from __future__ import annotations

import time
from dataclasses import replace

from core.engines.base import EngineCapability, EngineResult, ScanContext
from core.findings import infer_category
from core.scanner import scan_diff


class RegexEngine:
    name = "regex"

    def capability(self) -> EngineCapability:
        return EngineCapability(
            name=self.name,
            languages=frozenset({"*"}),
            categories=frozenset({"secret", "sast", "quality"}),
            version="1",
        )

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    def run(self, context: ScanContext) -> EngineResult:
        started = time.perf_counter()
        findings = scan_diff(
            list(context.diff_lines),
            context.rules,
            ignored_rule_ids=set(context.ignored_rule_ids),
            allowlist_regexes=context.line_allowlist,
            allowlist_path_regexes=context.path_allowlist,
            path_excludes=context.path_excludes,
            ignore_inline=context.ignore_inline,
            max_findings=context.max_findings,
            ignored_files=set(context.ignored_files),
            filter_placeholders=context.filter_placeholders,
            file_lines=context.file_lines,
            detect_ignore_file=context.detect_ignore_file,
        )
        normalized = tuple(
            replace(
                finding,
                engine=self.name,
                category=infer_category(
                    rule_id=finding.rule_id,
                    source=finding.source,
                    tags=finding.tags,
                    cwe=finding.cwe,
                    fixed_versions=finding.fixed_versions,
                    category=finding.category,
                ),
            )
            for finding in findings
        )
        return EngineResult(
            findings=normalized,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine=self.name,
        )
