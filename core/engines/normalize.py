"""Deterministic normalization and deduplication for schema-v3 findings."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from core.findings import SEVERITIES
from core.scanner import Finding

_SEVERITY_RANK = {severity: index for index, severity in enumerate(reversed(SEVERITIES))}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_ENGINE_RANK = {"regex": 1, "ast": 3, "semgrep": 3, "sca": 3, "unknown": 0}


def _engine_rank(finding: Finding) -> int:
    if finding.engine.startswith("ingest:"):
        return 1
    return _ENGINE_RANK.get(finding.engine, 1)


def _evidence_score(finding: Finding) -> tuple[int, int, int, int]:
    return (
        int(bool(finding.fix)),
        int(bool(finding.code_flows)),
        int(finding.column is not None),
        _engine_rank(finding),
    )


def _range(finding: Finding) -> tuple[int, int]:
    end = finding.end_line or finding.line_number
    return finding.line_number, max(finding.line_number, end)


def _overlaps(left: Finding, right: Finding) -> bool:
    if left.file != right.file or left.category != right.category:
        return False
    left_start, left_end = _range(left)
    right_start, right_end = _range(right)
    return left_start <= right_end and right_start <= left_end


def _compatible(left: Finding, right: Finding) -> bool:
    if left.rule_id == right.rule_id:
        return True
    if left.category != right.category:
        return False
    if left.cwe and right.cwe:
        return left.cwe == right.cwe
    return left.category == "secret"


def _merge(left: Finding, right: Finding) -> Finding:
    preferred = left if _evidence_score(left) >= _evidence_score(right) else right
    other = right if preferred is left else left
    severity = max(
        (left.severity, right.severity),
        key=lambda value: _SEVERITY_RANK.get(value, 0),
    )
    confidence = max(
        (left.confidence, right.confidence),
        key=lambda value: _CONFIDENCE_RANK.get(value, 0),
    )
    sources = list(preferred.also_reported_by)
    for candidate in (left, right):
        label = candidate.engine if candidate.engine.startswith("ingest:") else candidate.source
        if label and label not in sources:
            sources.append(label)
    tags = tuple(sorted(set(left.tags) | set(right.tags)))
    references = tuple(sorted(set(left.references) | set(right.references)))
    flows = preferred.code_flows or other.code_flows
    fix = preferred.fix or other.fix
    column = preferred.column if preferred.column is not None else other.column
    end_line = preferred.end_line or other.end_line
    end_column = preferred.end_column or other.end_column
    return replace(
        preferred,
        severity=severity,
        confidence=confidence,
        tags=tags,
        references=references,
        code_flows=flows,
        fix=fix,
        column=column,
        end_line=end_line,
        end_column=end_column,
        also_reported_by=tuple(ordered for ordered in sources if ordered != preferred.engine),
        blocking=left.blocking or right.blocking,
    )


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merges overlapping, compatible findings without merging categories."""
    buckets: dict[tuple[str, str], list[int]] = {}
    kept: list[Finding] = []
    for finding in findings:
        bucket = buckets.setdefault((finding.file, finding.category), [])
        merged_at: int | None = None
        for index in bucket:
            if _overlaps(kept[index], finding) and _compatible(kept[index], finding):
                kept[index] = _merge(kept[index], finding)
                merged_at = index
                break
        if merged_at is None:
            bucket.append(len(kept))
            kept.append(finding)
    return stable_order(kept)


def stable_order(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -_SEVERITY_RANK.get(finding.severity, 0),
            finding.file,
            finding.line_number,
            finding.rule_id,
            finding.fingerprint,
        ),
    )
