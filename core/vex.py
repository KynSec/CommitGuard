"""VEX (Vulnerability Exploitability eXchange) import, export, and filtering.

CommitGuard consumes OpenVEX and CycloneDX VEX documents to decide whether a
known dependency vulnerability is actually exploitable in this repository.
Statements with status ``not_affected`` or ``fixed`` keep the finding in the
report but mark it non-blocking, so a VEX decision never hides evidence.

The module is deliberately offline and deterministic: it parses local JSON and
never performs network requests.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.scanner import Finding

VEX_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})
_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

_CYCLONEDX_STATE_MAP = {
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "exploitable": "affected",
    "in_triage": "under_investigation",
}


class VEXError(RuntimeError):
    """Raised when a VEX document cannot be parsed or validated."""


@dataclass(frozen=True)
class VEXStatement:
    """A single exploitability assertion for one vulnerability."""

    vulnerability: str
    status: str
    products: tuple[str, ...] = ()
    justification: str = ""
    impact_statement: str = ""
    action_statement: str = ""
    timestamp: str = ""
    source: str = "openvex"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "vulnerability": {"name": self.vulnerability},
            "status": self.status,
        }
        if self.products:
            payload["products"] = [{"@id": product} for product in self.products]
        if self.justification:
            payload["justification"] = self.justification
        if self.impact_statement:
            payload["impact_statement"] = self.impact_statement
        if self.action_statement:
            payload["action_statement"] = self.action_statement
        if self.timestamp:
            payload["timestamp"] = self.timestamp
        return payload

    def matches(self, vulnerability_ids: Iterable[str], products: Iterable[str] = ()) -> bool:
        wanted = {_normalize_id(item) for item in vulnerability_ids if item}
        if _normalize_id(self.vulnerability) not in wanted:
            return False
        if not self.products:
            return True
        candidates: set[str] = set()
        for item in products:
            candidates.update(_product_keys(item))
        statement_products: set[str] = set()
        for product in self.products:
            statement_products.update(_product_keys(product))
        return bool(candidates & statement_products)


@dataclass(frozen=True)
class VEXDocument:
    """A parsed VEX document with OpenVEX and CycloneDX provenance."""

    statements: tuple[VEXStatement, ...] = ()
    author: str = ""
    role: str = ""
    timestamp: str = ""
    version: int = 1
    identifier: str = ""
    fmt: str = "openvex"

    def find(
        self,
        vulnerability_ids: Iterable[str],
        products: Iterable[str] = (),
    ) -> VEXStatement | None:
        for statement in self.statements:
            if statement.matches(vulnerability_ids, products):
                return statement
        return None

    def to_openvex(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "@context": _OPENVEX_CONTEXT,
            "author": self.author or "CommitGuard",
            "timestamp": self.timestamp or _now(),
            "version": self.version,
            "statements": [statement.to_dict() for statement in self.statements],
        }
        if self.identifier:
            document["@id"] = self.identifier
        if self.role:
            document["role"] = self.role
        return document

    def to_dict(self) -> dict[str, Any]:
        return self.to_openvex()


@dataclass(frozen=True)
class VEXApplication:
    """Result of applying a VEX document to a list of findings."""

    findings: tuple[Finding, ...]
    suppressed: int = 0
    annotated: int = 0
    unmatched: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.findings),
            "suppressed": self.suppressed,
            "annotated": self.annotated,
            "unmatched": list(self.unmatched),
        }


def _normalize_id(value: str) -> str:
    return value.strip().upper()


_ECOSYSTEM_PREFIXES = frozenset(
    {
        "apk",
        "cargo",
        "composer",
        "deb",
        "gem",
        "github",
        "golang",
        "maven",
        "npm",
        "nuget",
        "oci",
        "pypi",
        "rpm",
    }
)


def _product_keys(value: str) -> set[str]:
    """Returns matchable keys for a product id or a package reference."""
    text = value.strip().lower().split("?", 1)[0]
    text = text.removeprefix("pkg:")
    if "/" in text:
        prefix, remainder = text.split("/", 1)
        if prefix in _ECOSYSTEM_PREFIXES:
            text = remainder
    keys = {text}
    name = text.split("@", 1)[0]
    if name:
        keys.add(name)
    return keys


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _as_status(raw: str, *, source: str) -> str:
    value = str(raw or "").strip().lower()
    if source == "cyclonedx":
        value = _CYCLONEDX_STATE_MAP.get(value, value)
    if value not in VEX_STATUSES:
        raise VEXError(
            f"unsupported VEX status {raw!r}; expected one of {', '.join(VEX_STATUSES)}"
        )
    return value


def _statement_from_openvex(raw: Any) -> VEXStatement:
    if not isinstance(raw, dict):
        raise VEXError("each OpenVEX statement must be an object")
    vulnerability = raw.get("vulnerability")
    if isinstance(vulnerability, dict):
        name = vulnerability.get("name") or vulnerability.get("@id")
    else:
        name = vulnerability
    if not name:
        raise VEXError("OpenVEX statement is missing a vulnerability name")
    products: list[str] = []
    for product in raw.get("products") or ():
        if isinstance(product, dict):
            value = product.get("@id") or product.get("id") or product.get("name")
        else:
            value = product
        if value:
            products.append(str(value))
    return VEXStatement(
        vulnerability=str(name),
        status=_as_status(str(raw.get("status") or ""), source="openvex"),
        products=tuple(products),
        justification=str(raw.get("justification") or ""),
        impact_statement=str(raw.get("impact_statement") or ""),
        action_statement=str(raw.get("action_statement") or ""),
        timestamp=str(raw.get("timestamp") or ""),
        source="openvex",
    )


def _statement_from_cyclonedx(raw: Any) -> VEXStatement:
    if not isinstance(raw, dict):
        raise VEXError("each CycloneDX vulnerability must be an object")
    identifier = raw.get("id")
    if not identifier:
        raise VEXError("CycloneDX vulnerability is missing an id")
    analysis = raw.get("analysis") or {}
    if not isinstance(analysis, dict):
        analysis = {}
    products: list[str] = []
    for affected in raw.get("affects") or ():
        if isinstance(affected, dict):
            value = affected.get("ref") or affected.get("@id")
        else:
            value = affected
        if value:
            products.append(str(value))
    justification = str(analysis.get("justification") or "")
    detail = str(analysis.get("detail") or "")
    return VEXStatement(
        vulnerability=str(identifier),
        status=_as_status(
            str(analysis.get("state") or "under_investigation"), source="cyclonedx"
        ),
        products=tuple(products),
        justification=justification,
        impact_statement=detail,
        timestamp=str(raw.get("published") or ""),
        source="cyclonedx",
    )


def parse_vex(document: Any) -> VEXDocument:
    """Parses an OpenVEX or CycloneDX VEX mapping into a :class:`VEXDocument`."""
    if not isinstance(document, dict):
        raise VEXError("VEX document must be a JSON object")
    if str(document.get("bomFormat") or "").lower() == "cyclonedx":
        statements = tuple(
            _statement_from_cyclonedx(item)
            for item in document.get("vulnerabilities") or ()
        )
        metadata = document.get("metadata") or {}
        return VEXDocument(
            statements=statements,
            author=str((metadata.get("component") or {}).get("name") or ""),
            timestamp=str(metadata.get("timestamp") or ""),
            version=int(document.get("version") or 1),
            identifier=str(document.get("serialNumber") or ""),
            fmt="cyclonedx",
        )
    if "statements" not in document:
        raise VEXError("VEX document has neither OpenVEX statements nor CycloneDX vulnerabilities")
    statements = tuple(
        _statement_from_openvex(item) for item in document.get("statements") or ()
    )
    return VEXDocument(
        statements=statements,
        author=str(document.get("author") or ""),
        role=str(document.get("role") or ""),
        timestamp=str(document.get("timestamp") or ""),
        version=int(document.get("version") or 1),
        identifier=str(document.get("@id") or ""),
        fmt="openvex",
    )


def load_vex(path: str | Path) -> VEXDocument:
    vex_path = Path(path).expanduser()
    try:
        document = json.loads(vex_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise VEXError(f"could not read VEX document {vex_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VEXError(f"invalid JSON in VEX document {vex_path}: {exc}") from exc
    return parse_vex(document)


def finding_vulnerability_ids(finding: Finding) -> tuple[str, ...]:
    """Returns the advisory identifiers a finding can be matched against."""
    identifiers: list[str] = []
    if finding.rule_id.startswith("sca-"):
        identifiers.append(finding.rule_id[4:])
    identifiers.extend(finding.aliases)
    if finding.advisory_url:
        identifiers.append(finding.advisory_url.rstrip("/").rsplit("/", 1)[-1])
    seen: dict[str, None] = {}
    for identifier in identifiers:
        cleaned = identifier.strip()
        if cleaned:
            seen.setdefault(cleaned, None)
    return tuple(seen)


def finding_products(finding: Finding) -> tuple[str, ...]:
    """Returns product identifiers used to scope a VEX statement."""
    products: list[str] = []
    if finding.flagged_code:
        products.append(finding.flagged_code.replace("==", "@"))
    package = finding.flagged_code.split("==", 1)[0].strip() if finding.flagged_code else ""
    if package:
        products.append(package)
    if finding.file:
        products.append(finding.file)
    return tuple(products)


def apply_vex(
    findings: Iterable[Finding],
    document: VEXDocument,
    *,
    suppressing_statuses: frozenset[str] = SUPPRESSING_STATUSES,
) -> VEXApplication:
    """Applies VEX statements to findings without dropping any evidence."""
    applied: list[Finding] = []
    suppressed = 0
    annotated = 0
    matched_ids: set[str] = set()
    for finding in findings:
        identifiers = finding_vulnerability_ids(finding)
        statement = document.find(identifiers, finding_products(finding))
        if statement is None:
            applied.append(finding)
            continue
        matched_ids.add(_normalize_id(statement.vulnerability))
        provenance = dict(finding.provenance or {})
        provenance["vex"] = {
            "status": statement.status,
            "justification": statement.justification,
            "impact_statement": statement.impact_statement,
            "action_statement": statement.action_statement,
            "source": statement.source,
        }
        blocks = finding.blocking and statement.status not in suppressing_statuses
        updated = replace(finding, blocking=blocks, provenance=provenance)
        applied.append(updated)
        if finding.blocking and not blocks:
            suppressed += 1
        else:
            annotated += 1
    unmatched = tuple(
        statement.vulnerability
        for statement in document.statements
        if _normalize_id(statement.vulnerability) not in matched_ids
    )
    return VEXApplication(
        findings=tuple(applied),
        suppressed=suppressed,
        annotated=annotated,
        unmatched=unmatched,
    )


def export_openvex(
    findings: Iterable[Finding],
    *,
    author: str = "CommitGuard",
    status: str = "affected",
    timestamp: str | None = None,
) -> VEXDocument:
    """Builds an OpenVEX document from dependency findings.

    By default every dependency vulnerability is exported as ``affected``; a
    triage process can then edit the statuses to record exploitability
    decisions.
    """
    if status not in VEX_STATUSES:
        raise VEXError(
            f"unsupported VEX status {status!r}; expected one of {', '.join(VEX_STATUSES)}"
        )
    statements: list[VEXStatement] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        identifiers = finding_vulnerability_ids(finding)
        if not identifiers:
            continue
        products = finding_products(finding)
        key = (_normalize_id(identifiers[0]), ",".join(products))
        if key in seen:
            continue
        seen.add(key)
        action = ""
        if finding.fixed_versions:
            action = "Upgrade to " + ", ".join(finding.fixed_versions) + "."
        statements.append(
            VEXStatement(
                vulnerability=identifiers[0],
                status=status,
                products=products,
                action_statement=action,
                timestamp=timestamp or _now(),
            )
        )
    return VEXDocument(
        statements=tuple(statements),
        author=author,
        timestamp=timestamp or _now(),
        version=1,
        fmt="openvex",
    )
