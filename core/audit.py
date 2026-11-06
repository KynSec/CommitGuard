"""Quarterly audit artifacts assembled entirely from local files.

The audit never scans a repository, contacts a service, or loads a plugin.  It
reads committed reports, triage state, bounded history, and optional compliance
packs so a team can produce a quarterly review from CI artifacts and local
state alone.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from core import __version__
from core.compliance import (
    ComplianceError,
    ComplianceReport,
    discover_packs,
    evaluate_compliance,
    format_compliance_report,
)
from core.report_merge import MergeError, expand_report_inputs, merge_reports
from core.trends import TrendEntry, load_history
from core.triage import (
    TriageError,
    audit_triage,
    load_triage,
)


class AuditError(ValueError):
    """Raised when local audit inputs are invalid."""


@dataclass(frozen=True)
class LocalAudit:
    generated_at: str
    since: str
    until: str
    findings: int
    severity: dict[str, int]
    categories: dict[str, int]
    engines: dict[str, int]
    sources: tuple[dict[str, Any], ...]
    triage_entries: int
    triage_states: dict[str, int]
    triage_owners: dict[str, int]
    triage_issues: tuple[str, ...]
    history: tuple[TrendEntry, ...]
    warnings: tuple[str, ...]
    compliance: ComplianceReport | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "tool": {"name": "CommitGuard", "version": __version__},
            "generated_at": self.generated_at,
            "period": {"since": self.since, "until": self.until},
            "total": self.findings,
            "severity": dict(self.severity),
            "categories": dict(self.categories),
            "engines": dict(self.engines),
            "sources": list(self.sources),
            "triage": {
                "entries": self.triage_entries,
                "states": dict(self.triage_states),
                "owners": dict(self.triage_owners),
                "issues": list(self.triage_issues),
            },
            "history": [
                {
                    "timestamp": entry.timestamp,
                    "total": entry.total,
                    "critical": entry.critical,
                    "high": entry.high,
                    "medium": entry.medium,
                    "low": entry.low,
                    "info": entry.info,
                    "blocked": entry.blocked,
                    "threshold": entry.threshold,
                }
                for entry in self.history
            ],
            "warnings": list(self.warnings),
            "compliance": (
                self.compliance.to_dict() if self.compliance is not None else None
            ),
        }


def _parse_date(value: str | None, *, label: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AuditError(f"{label} must use YYYY-MM-DD") from exc


def _in_period(timestamp: str, since: date | None, until: date | None) -> bool:
    try:
        current = date.fromisoformat(timestamp[:10])
    except ValueError:
        return False
    if since is not None and current < since:
        return False
    return not (until is not None and current > until)


def _local_report_files(
    repo_root: Path, reports: Iterable[str | Path] | None
) -> list[Path]:
    inputs = [Path(item).expanduser() for item in reports or ()]
    if not inputs:
        default = repo_root / "commit_guard_reports"
        if default.is_dir():
            inputs = [default]
    if not inputs:
        return []
    resolved: list[Path] = []
    for item in inputs:
        if not item.is_absolute():
            item = (repo_root / item).resolve()
        resolved.append(item)
    return expand_report_inputs(resolved)


def build_local_audit(
    repo_root: str | Path = ".",
    *,
    reports: Iterable[str | Path] | None = None,
    triage_path: str | Path | None = None,
    history_path: str | Path | None = None,
    packs: Iterable[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> LocalAudit:
    root = Path(repo_root).expanduser().resolve()
    since_date = _parse_date(since, label="since")
    until_date = _parse_date(until, label="until")
    if since_date and until_date and since_date > until_date:
        raise AuditError("since must not be after until")

    warnings: list[str] = []
    files = _local_report_files(root, reports)
    if files:
        try:
            merged = merge_reports(files, repo_root=root)
        except (MergeError, OSError, ValueError) as exc:
            raise AuditError(str(exc)) from exc
        findings = list(merged.findings)
        sources = tuple(source.to_dict() for source in merged.sources)
    else:
        findings = []
        sources = ()
        warnings.append(
            "No local reports found; pass --reports or generate a JSON report first."
        )

    severity = Counter(finding.severity for finding in findings)
    categories = Counter(finding.category or "unknown" for finding in findings)
    engines = Counter(finding.engine or finding.source or "unknown" for finding in findings)

    try:
        triage = load_triage(root, triage_path)
    except TriageError as exc:
        raise AuditError(str(exc)) from exc
    present = {finding.fingerprint for finding in findings if finding.fingerprint}
    today = until_date or date.today()
    issues = tuple(audit_triage(triage, present, today=today))
    triage_states = Counter(entry.state for entry in triage.entries)
    triage_owners = Counter(entry.owner or "unassigned" for entry in triage.entries)

    history_file = (
        Path(history_path).expanduser()
        if history_path is not None
        else root / "commit_guard_reports" / "history.json"
    )
    if not history_file.is_absolute():
        history_file = (root / history_file).resolve()
    history = tuple(
        entry
        for entry in load_history(history_file)
        if _in_period(entry.timestamp, since_date, until_date)
    )

    compliance: ComplianceReport | None = None
    if packs:
        try:
            selected = discover_packs(root / "rules" / "compliance", names=packs)
            if not selected:
                selected = discover_packs(names=packs)
            compliance = evaluate_compliance(findings, selected)
        except ComplianceError as exc:
            raise AuditError(str(exc)) from exc

    period_until = until or today.isoformat()
    period_since = since or (history[0].timestamp[:10] if history else period_until)

    return LocalAudit(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        since=period_since,
        until=period_until,
        findings=len(findings),
        severity={key: severity.get(key, 0) for key in ("critical", "high", "medium", "low", "info")},
        categories=dict(sorted(categories.items())),
        engines=dict(sorted(engines.items())),
        sources=sources,
        triage_entries=len(triage.entries),
        triage_states=dict(sorted(triage_states.items())),
        triage_owners=dict(sorted(triage_owners.items())),
        triage_issues=issues,
        history=history,
        warnings=tuple(warnings),
        compliance=compliance,
    )


def format_local_audit(audit: LocalAudit, *, fmt: str = "markdown") -> str:
    if fmt == "json":
        return json.dumps(audit.to_dict(), indent=2) + "\n"
    lines = [
        "# CommitGuard Quarterly Audit",
        "",
        f"**Generated:** {audit.generated_at}",
        f"**CommitGuard:** v{__version__}",
        f"**Period:** {audit.since} to {audit.until}",
        f"**Findings:** {audit.findings}",
        "",
        "## Severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for key in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {key} | {audit.severity.get(key, 0)} |")
    lines.extend(["", "## Engines", "", "| Engine | Count |", "|---|---:|"])
    if audit.engines:
        for key, value in audit.engines.items():
            lines.append(f"| {key} | {value} |")
    else:
        lines.append("| _none_ | 0 |")
    lines.extend(["", "## Input reports", "", "| Report | Format | Findings |", "|---|---|---:|"])
    if audit.sources:
        for source in audit.sources:
            lines.append(
                f"| {source['path']} | {source['format']} | {source['finding_count']} |"
            )
    else:
        lines.append("| _none_ | - | 0 |")
    lines.extend(
        [
            "",
            "## Triage",
            "",
            f"Entries: {audit.triage_entries}",
            "",
            "| State | Count |",
            "|---|---:|",
        ]
    )
    if audit.triage_states:
        for key, value in audit.triage_states.items():
            lines.append(f"| {key} | {value} |")
    else:
        lines.append("| _none_ | 0 |")
    lines.extend(["", "### Triage issues", ""])
    if audit.triage_issues:
        lines.extend(f"- {issue}" for issue in audit.triage_issues)
    else:
        lines.append("No triage issues.")
    lines.extend(["", "## History", ""])
    if audit.history:
        for entry in audit.history:
            lines.append(
                f"- {entry.timestamp}: {entry.total} findings "
                f"(critical={entry.critical}, high={entry.high}, "
                f"blocked={'yes' if entry.blocked else 'no'})"
            )
    else:
        lines.append("No history entries in the selected period.")
    if audit.compliance is not None:
        lines.extend(["", "## Compliance", ""])
        compliance_text = format_compliance_report(audit.compliance)
        embedded: list[str] = []
        for line in compliance_text.splitlines():
            if line.startswith("#"):
                depth = len(line) - len(line.lstrip("#"))
                line = "#" * min(depth + 2, 6) + line[depth:]
            embedded.append(line)
        lines.append("\n".join(embedded))
    if audit.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in audit.warnings)
    return "\n".join(lines).rstrip() + "\n"


