"""Static local dashboard generation from committed reports and history.

The dashboard is a single self-contained HTML file.  It reads only local
artifacts, groups findings by triage owner or top-level path, and renders the
same trend data as the HTML scan report.  No JavaScript, fonts, or network
requests are used.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core import __version__
from core.report_merge import MergeError, load_report
from core.scanner import Finding
from core.trends import TrendEntry, build_trend_svg, load_history
from core.triage import TriageError, load_triage

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_NON_REPORT_NAMES = {"history.json", "dashboard.json", "triage.json"}


@dataclass(frozen=True)
class OwnershipGroup:
    owner: str
    total: int
    severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "total": self.total,
            "severity": dict(self.severity),
        }


@dataclass(frozen=True)
class DashboardData:
    generated_at: str
    findings: tuple[Finding, ...]
    history: tuple[TrendEntry, ...]
    ownership: tuple[OwnershipGroup, ...]
    categories: dict[str, int]
    reports: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def severity(self) -> dict[str, int]:
        counts = {severity: 0 for severity in _SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "tool": {"name": "CommitGuard", "version": __version__},
            "generated_at": self.generated_at,
            "total": len(self.findings),
            "severity": self.severity,
            "categories": dict(self.categories),
            "ownership": [group.to_dict() for group in self.ownership],
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
            "reports": list(self.reports),
            "warnings": list(self.warnings),
        }


def _report_files(inputs: Iterable[str | Path] | None, root: Path) -> list[Path]:
    if not inputs:
        default = root / "commit_guard_reports"
        candidates = [default] if default.is_dir() else []
    else:
        candidates = [Path(item).expanduser() for item in inputs]
    files: list[Path] = []
    for candidate in candidates:
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        if candidate.is_dir():
            files.extend(
                sorted(
                    path
                    for path in candidate.rglob("*")
                    if path.is_file()
                    and path.suffix.lower() in {".json", ".sarif"}
                    and path.name.lower() not in _NON_REPORT_NAMES
                )
            )
        elif candidate.is_file():
            files.append(candidate)
    unique: dict[str, Path] = {}
    for path in files:
        try:
            unique[str(path.resolve())] = path.resolve()
        except OSError:
            continue
    return sorted(unique.values(), key=lambda item: str(item))


def _owner_for(
    finding: Finding, owners: Mapping[str, str], default_owner: str
) -> str:
    owner = owners.get(finding.fingerprint) or owners.get(finding.id)
    if owner:
        return owner
    parts = [part for part in finding.file.split("/") if part]
    if len(parts) > 1:
        return parts[0]
    return default_owner


def build_dashboard_data(
    repo_root: str | Path = ".",
    *,
    reports: Iterable[str | Path] | None = None,
    history: str | Path | None = None,
    owner: str = "unassigned",
) -> DashboardData:
    root = Path(repo_root).expanduser().resolve()
    files = _report_files(reports, root)
    findings: list[Finding] = []
    warnings: list[str] = []
    used_reports: list[str] = []
    for path in files:
        try:
            report_findings, _source = load_report(path, repo_root=root)
        except (MergeError, OSError, ValueError) as exc:
            warnings.append(f"{path}: {exc}")
            continue
        findings.extend(report_findings)
        used_reports.append(str(path))
    if not files:
        warnings.append("No local reports found; run `commit-guard scan --format json` first.")

    unique: dict[str, Finding] = {}
    for finding in findings:
        unique[finding.fingerprint or f"{finding.file}:{finding.line_number}:{finding.rule_id}"] = finding
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            _SEVERITY_ORDER.index(item.severity)
            if item.severity in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            item.file,
            item.line_number,
            item.rule_id,
        ),
    )

    history_path = Path(history).expanduser() if history else root / "commit_guard_reports" / "history.json"
    if not history_path.is_absolute():
        history_path = (root / history_path).resolve()
    entries = tuple(load_history(history_path))

    owners: dict[str, str] = {}
    try:
        triage = load_triage(root)
        for entry in triage.entries:
            if entry.owner:
                owners[entry.fingerprint] = entry.owner
    except (TriageError, OSError):
        pass

    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for finding in ordered:
        grouped[_owner_for(finding, owners, owner)][finding.severity] += 1
    ownership = tuple(
        OwnershipGroup(
            owner=name,
            total=sum(counts.values()),
            severity={severity: counts.get(severity, 0) for severity in _SEVERITY_ORDER},
        )
        for name, counts in sorted(grouped.items(), key=lambda item: (-sum(item[1].values()), item[0]))
    )
    category_counts = Counter(finding.category or "unknown" for finding in ordered)
    return DashboardData(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        findings=tuple(ordered),
        history=entries,
        ownership=ownership,
        categories=dict(sorted(category_counts.items())),
        reports=tuple(used_reports),
        warnings=tuple(warnings),
    )


_CSS = """
:root { color-scheme: light; }
body { margin: 0; padding: 2rem; font-family: system-ui, -apple-system, Segoe UI, sans-serif;
  color: #0f172a; background: #f1f5f9; }
main { max-width: 1200px; margin: 0 auto; }
header, section { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1rem; }
h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
h2 { margin-top: 0; font-size: 1.15rem; }
.meta { color: #475569; font-size: .9rem; }
.cards { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1rem; }
.card { min-width: 100px; border: 1px solid #e2e8f0; border-radius: 8px;
  padding: .6rem .8rem; }
.card b { display: block; font-size: 1.4rem; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { text-align: left; padding: .45rem .35rem; border-bottom: 1px solid #e2e8f0;
  vertical-align: top; }
th { color: #475569; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .82rem; }
.sev { font-weight: 700; text-transform: uppercase; }
.sev.critical { color: #991b1b; } .sev.high { color: #c2410c; }
.sev.medium { color: #a16207; } .sev.low { color: #1d4ed8; }
.sev.info { color: #475569; }
.empty, .note { color: #475569; }
.trend { width: 100%; height: auto; margin-top: .5rem; }
""".strip()


def _severity_cells(group: OwnershipGroup) -> str:
    return "".join(
        f"<td>{group.severity.get(severity, 0)}</td>"
        for severity in _SEVERITY_ORDER
    )


def render_dashboard(data: DashboardData) -> str:
    severity = data.severity
    trend = build_trend_svg(list(data.history)) if data.history else ""
    trend_section = (
        f"<section><h2>Finding trend</h2>{trend}</section>" if trend else ""
    )
    warnings = (
        "<section><h2>Warnings</h2><ul>"
        + "".join(f"<li class=\"note\">{html.escape(item)}</li>" for item in data.warnings)
        + "</ul></section>"
        if data.warnings
        else ""
    )
    ownership_rows = "".join(
        "<tr>"
        f"<td>{html.escape(group.owner)}</td>"
        f"<td>{group.total}</td>"
        f"{_severity_cells(group)}"
        "</tr>"
        for group in data.ownership
    ) or '<tr><td colspan="7" class="empty">No findings.</td></tr>'
    category_rows = "".join(
        f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>"
        for category, count in data.categories.items()
    ) or '<tr><td colspan="2" class="empty">No findings.</td></tr>'
    finding_rows = "".join(
        "<tr>"
        f'<td class="sev {html.escape(finding.severity)}">{html.escape(finding.severity)}</td>'
        f"<td><code>{html.escape(finding.rule_id)}</code></td>"
        f"<td><code>{html.escape(finding.file)}:{finding.line_number}</code></td>"
        f"<td>{html.escape(finding.category or 'unknown')}</td>"
        f"<td>{html.escape(finding.description)}</td>"
        "</tr>"
        for finding in data.findings[:500]
    ) or '<tr><td colspan="5" class="empty">No findings.</td></tr>'
    truncated = (
        '<p class="note">Showing the first 500 findings.</p>'
        if len(data.findings) > 500
        else ""
    )
    report_rows = "".join(
        f"<tr><td><code>{html.escape(path)}</code></td></tr>"
        for path in data.reports
    ) or '<tr><td class="empty">No reports.</td></tr>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CommitGuard security dashboard</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header>
<h1>CommitGuard security dashboard</h1>
<p class="meta">Generated {html.escape(data.generated_at)} · CommitGuard
v{html.escape(__version__)} · Local artifacts only</p>
<div class="cards">
<div class="card"><b>{len(data.findings)}</b>Total</div>
{''.join(f'<div class="card"><b>{severity.get(name, 0)}</b>{name.title()}</div>' for name in _SEVERITY_ORDER)}
</div>
</header>
{warnings}
<section>
<h2>Ownership groups</h2>
<table>
<thead><tr><th>Owner</th><th>Total</th><th>Critical</th><th>High</th>
<th>Medium</th><th>Low</th><th>Info</th></tr></thead>
<tbody>{ownership_rows}</tbody>
</table>
</section>
<section>
<h2>Categories</h2>
<table><thead><tr><th>Category</th><th>Findings</th></tr></thead>
<tbody>{category_rows}</tbody></table>
</section>
{trend_section}
<section>
<h2>Findings</h2>
{truncated}
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Category</th>
<th>Description</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
</section>
<section>
<h2>Source reports</h2>
<table><thead><tr><th>Path</th></tr></thead><tbody>{report_rows}</tbody></table>
</section>
</main>
</body>
</html>
"""


def write_dashboard(data: DashboardData, output: str | Path) -> Path:
    target = Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_dashboard(data), encoding="utf-8")
    return target.resolve()


def dashboard_json(data: DashboardData) -> str:
    return json.dumps(data.to_dict(), indent=2) + "\n"
