"""Schema v3 helpers for :class:`core.scanner.Finding`.

The model itself stays in ``core.scanner`` for backwards compatibility.  This
module owns the additive schema rules, defensive serialization, and path
canonicalization used by reports, ingest adapters, policy, and the GUI.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

SCHEMA_VERSION = 3
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
CATEGORIES = (
    "secret",
    "sast",
    "dependency",
    "iac",
    "container",
    "license",
    "quality",
    "web",
    "authz",
    "logic",
    "race",
    "supply-chain",
    "unknown",
)
_ENGINES = ("regex", "ast", "semgrep", "sca", "ingest", "unknown")

_SECRET_MARKERS = (
    "secret",
    "credential",
    "password",
    "api-key",
    "api_key",
    "token",
    "private-key",
    "private_key",
    "gitleaks",
    "cwe-798",
    "cwe-259",
    "cwe-321",
)
_SUPPLY_CHAIN_MARKERS = (
    "supply-chain",
    "supplychain",
    "dependency-confusion",
    "install-script",
    "github-actions",
    "cwe-506",
    "cwe-829",
)
_DEPENDENCY_MARKERS = (
    "dependency",
    "vulnerable package",
    "osv",
    "cve-",
    "ghsa-",
    "pip-audit",
    "npm-audit",
    "snyk",
    "dependabot",
    "typosquat",
    "malicious package",
)
_WEB_MARKERS = (
    "web",
    "ssrf",
    "xss",
    "csrf",
    "xxe",
    "open-redirect",
    "open redirect",
    "cors",
    "cwe-79",
    "cwe-601",
    "cwe-611",
    "cwe-918",
    "cwe-942",
    "cwe-1336",
    "cwe-943",
)
_AUTHZ_MARKERS = (
    "authz",
    "authorization",
    "access-control",
    "access control",
    "idor",
    "privilege",
    "cwe-269",
    "cwe-285",
    "cwe-639",
    "cwe-862",
    "cwe-863",
    "cwe-915",
)
_LOGIC_MARKERS = (
    "business-logic",
    "business logic",
    "logic",
    "payment",
    "cwe-840",
)
_RACE_MARKERS = ("race", "toctou", "cwe-367")
_IAC_MARKERS = ("iac", "terraform", "kubernetes", "checkov", "cloudformation", "helm")
_CONTAINER_MARKERS = ("container", "docker", "image", "trivy", "grype")
_LICENSE_MARKERS = ("license", "copyleft")
_QUALITY_MARKERS = ("quality", "lint", "style", "ruff", "eslint", "shellcheck")

_REQUIRED_FIELDS = ("file", "line", "rule_id", "severity", "description")
_KNOWN_FIELDS = {
    "schema_version",
    "id",
    "file",
    "line",
    "column",
    "end_line",
    "end_column",
    "rule_id",
    "engine",
    "category",
    "severity",
    "confidence",
    "source",
    "description",
    "flagged_code",
    "redacted_code",
    "fingerprint",
    "tags",
    "cwe",
    "blocking",
    "baseline_state",
    "fixed_versions",
    "aliases",
    "advisory_url",
    "fix",
    "references",
    "code_flows",
    "also_reported_by",
    "rule_version",
    "pack_version",
    "provenance",
}


class FindingSchemaError(ValueError):
    """Raised when a serialized finding cannot be trusted."""


def canonical_path(raw: str | Path, repo_root: str | Path | None = None) -> str:
    """Returns a safe repository-relative POSIX path.

    Absolute paths are accepted only when they resolve inside ``repo_root``.
    Paths escaping the repository with ``..`` or containing NUL bytes are
    rejected rather than silently rewritten.
    """
    if raw is None:
        raise FindingSchemaError("finding path is missing")
    text = unquote(str(raw)).replace("\\", "/").strip()
    if not text or "\x00" in text:
        raise FindingSchemaError("finding path is empty or contains NUL")
    parsed = urlparse(text)
    if parsed.scheme == "file":
        text = unquote(parsed.path)
    elif parsed.scheme and not re.match(r"^[A-Za-z]:/", text):
        raise FindingSchemaError(f"unsupported URI scheme in path: {parsed.scheme}")
    if re.match(r"^[A-Za-z]:/", text):
        text = "/" + text
    if text.startswith("/"):
        if repo_root is None:
            raise FindingSchemaError(f"absolute path outside a repository: {text}")
        root = Path(repo_root).expanduser().resolve()
        candidate = Path(text).resolve()
        try:
            text = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise FindingSchemaError(
                f"absolute path is outside the repository: {text}"
            ) from exc
    text = posixpath.normpath(text)
    if text in (".", "") or text.startswith("../") or text == "..":
        raise FindingSchemaError(f"path escapes the repository: {raw}")
    return text.removeprefix("./")


def infer_engine(source: str, rule_id: str = "", engine: str = "") -> str:
    if engine:
        return engine
    lowered = (source or "").lower()
    if lowered.startswith("ingest:"):
        return lowered
    if lowered in _ENGINES:
        return lowered
    rule_lower = (rule_id or "").lower()
    if lowered == "ast" or "ast" in lowered or "ast" in rule_lower or "taint" in rule_lower:
        return "ast"
    if lowered in {"osv", "sca", "pip-audit", "npm-audit"}:
        return "sca"
    if lowered.startswith("ingest"):
        return lowered
    return "regex"


def infer_category(
    *,
    rule_id: str,
    source: str,
    tags: tuple[str, ...] = (),
    cwe: str | None = None,
    fixed_versions: tuple[str, ...] = (),
    category: str = "",
) -> str:
    if category:
        return category
    text = " ".join(
        (rule_id or "", source or "", " ".join(tags), cwe or "")
    ).lower()
    if any(marker in text for marker in _SECRET_MARKERS):
        return "secret"
    if any(marker in text for marker in _SUPPLY_CHAIN_MARKERS):
        return "supply-chain"
    if fixed_versions or any(marker in text for marker in _DEPENDENCY_MARKERS):
        return "dependency"
    if any(marker in text for marker in _CONTAINER_MARKERS):
        if "trivy" in text and "os-pkgs" in text:
            return "dependency"
        return "container"
    if any(marker in text for marker in _IAC_MARKERS):
        return "iac"
    if any(marker in text for marker in _LICENSE_MARKERS):
        return "license"
    if any(marker in text for marker in _QUALITY_MARKERS):
        return "quality"
    if any(marker in text for marker in _AUTHZ_MARKERS):
        return "authz"
    if any(marker in text for marker in _LOGIC_MARKERS):
        return "logic"
    if any(marker in text for marker in _RACE_MARKERS):
        return "race"
    if any(marker in text for marker in _WEB_MARKERS):
        return "web"
    return "sast"


def infer_confidence(engine: str, severity: str = "") -> str:
    if engine in {"ast", "semgrep", "sca"}:
        return "high"
    if engine == "regex":
        return "medium"
    if engine.startswith("ingest:"):
        return "medium"
    return "low"


def fingerprint(rule_id: str, path: str, code: str = "") -> str:
    payload = f"{rule_id}\0{path}\0{code.strip()}".encode("utf-8", "replace")
    return hashlib.sha256(payload).hexdigest()[:16]


def _as_tuple(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def validate_finding_dict(item: Mapping[str, Any]) -> None:
    if not isinstance(item, Mapping):
        raise FindingSchemaError("finding must be an object")
    for key in _REQUIRED_FIELDS:
        if key not in item:
            raise FindingSchemaError(f"finding is missing required field '{key}'")
    try:
        schema_version = int(item.get("schema_version", SCHEMA_VERSION))
    except (TypeError, ValueError) as exc:
        raise FindingSchemaError("schema_version must be an integer") from exc
    if schema_version > SCHEMA_VERSION:
        raise FindingSchemaError(
            f"unsupported finding schema {schema_version}; "
            f"this CommitGuard supports up to {SCHEMA_VERSION}"
        )
    severity = str(item.get("severity", "")).lower()
    if severity not in SEVERITIES:
        raise FindingSchemaError(f"invalid severity: {severity!r}")
    confidence = str(item.get("confidence", "medium")).lower()
    if confidence not in CONFIDENCES:
        raise FindingSchemaError(f"invalid confidence: {confidence!r}")
    try:
        if int(item["line"]) < 1:
            raise FindingSchemaError("line must be >= 1")
    except (TypeError, ValueError) as exc:
        raise FindingSchemaError("line must be an integer") from exc
    canonical_path(str(item["file"]))


def finding_to_dict(finding: Any, *, show_secrets: bool = False) -> dict[str, Any]:
    """Serializes a Finding using schema v3 while retaining legacy fields."""
    return {
        "schema_version": SCHEMA_VERSION,
        "id": getattr(finding, "id", "") or finding.fingerprint,
        "file": finding.file,
        "line": finding.line_number,
        "column": getattr(finding, "column", None),
        "end_line": getattr(finding, "end_line", None),
        "end_column": getattr(finding, "end_column", None),
        "rule_id": finding.rule_id,
        "engine": getattr(finding, "engine", "") or infer_engine(finding.source, finding.rule_id),
        "category": getattr(finding, "category", "")
        or infer_category(
            rule_id=finding.rule_id,
            source=finding.source,
            tags=finding.tags,
            cwe=finding.cwe,
            fixed_versions=finding.fixed_versions,
        ),
        "severity": finding.severity,
        "confidence": getattr(finding, "confidence", "medium"),
        "source": finding.source,
        "description": finding.description,
        "cwe": finding.cwe,
        "tags": list(finding.tags),
        "fingerprint": finding.fingerprint,
        "blocking": finding.blocking,
        "baseline_state": finding.baseline_state,
        "fixed_versions": list(finding.fixed_versions),
        "aliases": list(finding.aliases),
        "advisory_url": finding.advisory_url,
        "fix": getattr(finding, "fix", None),
        "references": list(getattr(finding, "references", ())),
        "code_flows": list(getattr(finding, "code_flows", ())),
        "also_reported_by": list(getattr(finding, "also_reported_by", ())),
        "rule_version": getattr(finding, "rule_version", ""),
        "pack_version": getattr(finding, "pack_version", ""),
        "provenance": dict(getattr(finding, "provenance", {}) or {}),
        "flagged_code": finding.display_code(show_secrets),
    }


def finding_from_dict(item: Mapping[str, Any]) -> Any:
    """Builds a Finding from a v2 or v3 JSON object.

    Unknown properties are preserved under ``provenance.unknown`` so adapters
    never silently drop tool data.
    """
    from core.scanner import Finding

    validate_finding_dict(item)
    known = set(_KNOWN_FIELDS)
    unknown = {key: value for key, value in item.items() if key not in known}
    provenance = item.get("provenance")
    if not isinstance(provenance, dict):
        provenance = {}
    provenance = dict(provenance)
    if unknown:
        provenance.setdefault("unknown", {}).update(unknown)
    source = str(item.get("source") or "ingest:unknown")
    rule_id = str(item["rule_id"])
    engine = str(
        item.get("engine") or infer_engine(source, rule_id)
    )
    category = str(
        item.get("category")
        or infer_category(
            rule_id=rule_id,
            source=source,
            tags=tuple(str(tag) for tag in _as_tuple(item.get("tags"))),
            cwe=str(item["cwe"]) if item.get("cwe") else None,
            fixed_versions=tuple(str(v) for v in _as_tuple(item.get("fixed_versions"))),
        )
    )
    code = str(item.get("flagged_code") or "")
    path = canonical_path(str(item["file"]))
    fp = str(item.get("fingerprint") or fingerprint(rule_id, path, code))
    return Finding(
        file=path,
        line_number=int(item["line"]),
        rule_id=rule_id,
        description=str(item["description"]),
        severity=str(item["severity"]).lower(),
        source=source,
        flagged_code=code,
        redacted_code=str(item.get("redacted_code") or ""),
        fingerprint=fp,
        tags=tuple(str(tag) for tag in _as_tuple(item.get("tags"))),
        cwe=str(item["cwe"]) if item.get("cwe") else None,
        blocking=bool(item.get("blocking", True)),
        baseline_state=str(item.get("baseline_state", "new")),
        fixed_versions=tuple(str(v) for v in _as_tuple(item.get("fixed_versions"))),
        aliases=tuple(str(v) for v in _as_tuple(item.get("aliases"))),
        advisory_url=str(item["advisory_url"]) if item.get("advisory_url") else None,
        id=str(item.get("id") or fp),
        engine=engine,
        category=category,
        confidence=str(item.get("confidence", "medium")).lower(),
        column=int(item["column"]) if item.get("column") is not None else None,
        end_line=int(item["end_line"]) if item.get("end_line") is not None else None,
        end_column=int(item["end_column"])
        if item.get("end_column") is not None
        else None,
        fix=dict(item["fix"]) if isinstance(item.get("fix"), dict) else None,
        references=tuple(str(v) for v in _as_tuple(item.get("references"))),
        code_flows=tuple(
            dict(flow) if isinstance(flow, dict) else {"text": str(flow)}
            for flow in _as_tuple(item.get("code_flows"))
        ),
        also_reported_by=tuple(
            str(v) for v in _as_tuple(item.get("also_reported_by"))
        ),
        rule_version=str(item.get("rule_version") or ""),
        pack_version=str(item.get("pack_version") or ""),
        provenance=provenance,
    )


def extract_findings(payload: Any) -> list[Any]:
    """Extracts findings from a CommitGuard JSON object or bare list."""
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, Mapping):
        try:
            version = int(payload.get("schema_version", SCHEMA_VERSION))
        except (TypeError, ValueError) as exc:
            raise FindingSchemaError("schema_version must be an integer") from exc
        if version > SCHEMA_VERSION:
            raise FindingSchemaError(
                f"unsupported report schema {version}; expected <= {SCHEMA_VERSION}"
            )
        items = payload.get("findings", [])
    else:
        raise FindingSchemaError("report must be a JSON object or list")
    if not isinstance(items, list):
        raise FindingSchemaError("report.findings must be a list")
    if len(items) > 100_000:
        raise FindingSchemaError("report contains too many findings")
    return [finding_from_dict(item) for item in items]
