"""Merge CommitGuard JSON, SARIF, and native tool reports."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core import __version__
from core.engines.normalize import dedupe_findings
from core.findings import SCHEMA_VERSION, extract_findings, finding_to_dict
from core.ingest import IngestError, ingest_data, load_json
from core.scanner import Finding


class MergeError(ValueError):
    """Raised when inputs cannot be merged safely."""


@dataclass(frozen=True)
class ReportSource:
    path: str
    format: str
    digest: str
    finding_count: int
    tool_versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "digest": self.digest,
            "finding_count": self.finding_count,
            "tool_versions": dict(self.tool_versions),
        }


@dataclass(frozen=True)
class MergedReport:
    findings: tuple[Finding, ...]
    sources: tuple[ReportSource, ...]
    tool_versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "CommitGuard", "version": __version__},
            "inputs": [source.to_dict() for source in self.sources],
            "tool_versions": dict(self.tool_versions),
            "total": len(self.findings),
            "findings": [finding_to_dict(finding) for finding in self.findings],
        }


def _detect_format(document: Any) -> str:
    if isinstance(document, Mapping) and "runs" in document:
        return "sarif"
    if isinstance(document, Mapping) and "findings" in document:
        return "commitguard-json"
    return "native"


def load_report(
    path: str | Path, *, repo_root: str | Path | None = None
) -> tuple[list[Finding], ReportSource]:
    report_path = Path(path).expanduser()
    document = load_json(report_path)
    report_format = _detect_format(document)
    if report_format == "sarif":
        findings = ingest_data(document, tool="sarif", repo_root=repo_root)
        tool_versions = {}
        for run in document.get("runs", []):
            driver = ((run.get("tool") or {}).get("driver") or {})
            name = str(driver.get("name") or "unknown")
            version = str(driver.get("version") or "")
            if version:
                tool_versions[name] = version
    elif report_format == "commitguard-json":
        findings = extract_findings(document)
        tool = document.get("tool") if isinstance(document, Mapping) else {}
        version = str((tool or {}).get("version") or "") if isinstance(tool, Mapping) else ""
        tool_versions = {"CommitGuard": version} if version else {}
    else:
        findings = ingest_data(document, tool="auto", repo_root=repo_root)
        tool_versions = {}
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "utf-8", "replace"
        )
    ).hexdigest()[:16]
    source = ReportSource(
        path=str(report_path),
        format=report_format,
        digest=digest,
        finding_count=len(findings),
        tool_versions=tool_versions,
    )
    return findings, source


def merge_reports(
    paths: Iterable[str | Path], *, repo_root: str | Path | None = None
) -> MergedReport:
    findings: list[Finding] = []
    sources: list[ReportSource] = []
    versions: dict[str, str] = {"commit-guard": __version__}
    for path in paths:
        try:
            report_findings, source = load_report(path, repo_root=repo_root)
        except IngestError as exc:
            raise MergeError(str(exc)) from exc
        findings.extend(report_findings)
        sources.append(source)
        versions.update(source.tool_versions)
    return MergedReport(
        findings=tuple(dedupe_findings(findings)),
        sources=tuple(sources),
        tool_versions=versions,
    )


def write_merged_json(report: MergedReport, path: str | Path) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    return target
