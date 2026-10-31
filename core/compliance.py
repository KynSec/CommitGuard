"""Defensible compliance mapping for findings.

Mappings are evidence aids, not certifications.  Each control entry cites the
control identifier and the rules or CWEs it covers.  A finding contributes to a
control when its ``cwe`` value, ``rule_id``, category, or tags match an entry.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from core.scanner import Finding

DISCLAIMER = (
    "Mapping is not certification. Controls marked partial or organizational "
    "require evidence outside CommitGuard."
)
DEFAULT_PACK_DIR = Path(__file__).resolve().parent.parent / "rules" / "compliance"


class ComplianceError(ValueError):
    """Raised when a compliance pack cannot be loaded."""


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    cwes: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    confidence: str = "medium"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "cwes": list(self.cwes),
            "rules": list(self.rules),
            "tags": list(self.tags),
            "categories": list(self.categories),
            "confidence": self.confidence,
            "note": self.note,
        }


@dataclass(frozen=True)
class CompliancePack:
    id: str
    name: str
    version: str
    controls: tuple[Control, ...]
    source: str = ""
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "disclaimer": self.disclaimer,
            "controls": [control.to_dict() for control in self.controls],
        }


@dataclass(frozen=True)
class ControlCoverage:
    pack_id: str
    control_id: str
    title: str
    finding_count: int
    highest_severity: str
    confidence: str
    rules: tuple[str, ...] = ()
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "control_id": self.control_id,
            "title": self.title,
            "finding_count": self.finding_count,
            "highest_severity": self.highest_severity,
            "confidence": self.confidence,
            "rules": list(self.rules),
            "note": self.note,
        }


@dataclass(frozen=True)
class ComplianceReport:
    packs: tuple[CompliancePack, ...]
    coverage: tuple[ControlCoverage, ...]
    finding_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "disclaimer": DISCLAIMER,
            "finding_count": self.finding_count,
            "packs": [pack.to_dict() for pack in self.packs],
            "coverage": [item.to_dict() for item in self.coverage],
        }


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _control(raw: Mapping[str, Any]) -> Control:
    identifier = str(raw.get("id") or "").strip()
    if not identifier:
        raise ComplianceError("control is missing an id")
    return Control(
        id=identifier,
        title=str(raw.get("title") or raw.get("name") or identifier),
        cwes=tuple(value.upper() for value in _tuple(raw.get("cwes"))),
        rules=_tuple(raw.get("rules")),
        tags=_tuple(raw.get("tags")),
        categories=_tuple(raw.get("categories")),
        confidence=str(raw.get("confidence") or "medium"),
        note=str(raw.get("note") or ""),
    )


def load_pack(path: str | Path) -> CompliancePack:
    pack_path = Path(path).expanduser()
    try:
        text = pack_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ComplianceError(f"could not read compliance pack {pack_path}: {exc}") from exc
    try:
        document = (
            json.loads(text)
            if pack_path.suffix.lower() == ".json"
            else yaml.safe_load(text)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ComplianceError(f"invalid compliance pack {pack_path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise ComplianceError(f"compliance pack {pack_path} must be an object")
    controls = document.get("controls")
    if not isinstance(controls, list):
        raise ComplianceError(f"compliance pack {pack_path} is missing controls[]")
    identifier = str(document.get("id") or pack_path.stem)
    return CompliancePack(
        id=identifier,
        name=str(document.get("name") or identifier),
        version=str(document.get("version") or ""),
        controls=tuple(
            _control(control)
            for control in controls
            if isinstance(control, Mapping)
        ),
        source=str(pack_path),
        disclaimer=str(document.get("disclaimer") or DISCLAIMER),
    )


def discover_packs(
    directory: str | Path | None = None,
    *,
    names: Iterable[str] | None = None,
) -> tuple[CompliancePack, ...]:
    base = Path(directory).expanduser() if directory else DEFAULT_PACK_DIR
    if not base.is_dir():
        return ()
    requested = {name.lower() for name in names or ()}
    packs: list[CompliancePack] = []
    for path in sorted(base.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        pack = load_pack(path)
        if requested and requested.isdisjoint(
            {pack.id.lower(), path.stem.lower(), pack.name.lower()}
        ):
            continue
        packs.append(pack)
    return tuple(packs)


def _matches(control: Control, finding: Finding) -> bool:
    cwe = (finding.cwe or "").upper()
    if cwe and cwe in control.cwes:
        return True
    if control.rules and finding.rule_id in control.rules:
        return True
    tags = {tag.lower() for tag in finding.tags}
    if control.tags and tags & {tag.lower() for tag in control.tags}:
        return True
    category = (finding.category or "").lower()
    if control.categories and category in {
        candidate.lower() for candidate in control.categories
    }:
        return True
    if control.cwes:
        for candidate in control.cwes:
            if candidate.replace("CWE-", "").isdigit() and candidate == cwe:
                return True
    return False


def evaluate_compliance(
    findings: Iterable[Finding],
    packs: Iterable[CompliancePack] | None = None,
) -> ComplianceReport:
    selected = tuple(packs if packs is not None else discover_packs())
    finding_list = list(findings)
    coverage: list[ControlCoverage] = []
    for pack in selected:
        for control in pack.controls:
            matches = [finding for finding in finding_list if _matches(control, finding)]
            if not matches:
                continue
            highest = min(
                (finding.severity for finding in matches),
                key=lambda value: (
                    _SEVERITY_ORDER.index(value)
                    if value in _SEVERITY_ORDER
                    else len(_SEVERITY_ORDER)
                ),
            )
            coverage.append(
                ControlCoverage(
                    pack_id=pack.id,
                    control_id=control.id,
                    title=control.title,
                    finding_count=len(matches),
                    highest_severity=highest,
                    confidence=control.confidence,
                    rules=tuple(sorted({finding.rule_id for finding in matches})),
                    note=control.note,
                )
            )
    coverage.sort(key=lambda item: (item.pack_id, item.control_id))
    return ComplianceReport(
        packs=selected,
        coverage=tuple(coverage),
        finding_count=len(finding_list),
    )


def format_compliance_report(report: ComplianceReport, *, fmt: str = "markdown") -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2) + "\n"
    lines = [
        "# CommitGuard compliance mapping",
        "",
        f"> {DISCLAIMER}",
        "",
        f"Findings evaluated: {report.finding_count}",
        "",
    ]
    if not report.packs:
        lines.append("No compliance packs found.")
        return "\n".join(lines) + "\n"
    for pack in report.packs:
        entries = [item for item in report.coverage if item.pack_id == pack.id]
        lines.extend(
            [
                f"## {pack.name} {pack.version}".rstrip(),
                "",
            ]
        )
        if not entries:
            lines.append("No mapped findings.")
            lines.append("")
            continue
        lines.extend(
            [
                "| Control | Title | Findings | Highest severity | Confidence | Rules |",
                "|---|---|---:|---|---|---|",
            ]
        )
        for item in entries:
            rules = ", ".join(item.rules[:5])
            if len(item.rules) > 5:
                rules += ", ..."
            lines.append(
                f"| {item.control_id} | {item.title} | {item.finding_count} | "
                f"{item.highest_severity} | {item.confidence} | {rules} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"
