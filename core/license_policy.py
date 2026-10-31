"""Dependency license policy evaluation.

License results are intentionally separate from the security gate.  A
disallowed or unknown license is a release or procurement decision, not a
vulnerability finding, and must not silently change ``scan`` exit codes.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.sbom import (
    UNKNOWN_LICENSE,
    PackageLicense,
    collect_licenses,
    license_index,
    normalize_name,
)
from core.sca import Package, collect_packages

DEFAULT_ALLOW = (
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
)
DEFAULT_DENY = (
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "BUSL-1.1",
    "Commons-Clause",
    "Elastic-2.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL-1.0",
)
DEFAULT_REVIEW = (
    "CDDL-1.0",
    "EPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
)

_ALIASES = {
    "agpl-3.0": "AGPL-3.0-only",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "mit license": "MIT",
    "mozilla public license 2.0": "MPL-2.0",
    "new bsd license": "BSD-3-Clause",
    "python software foundation license": "Python-2.0",
}
_CANONICAL = {
    value.lower(): value
    for value in (*DEFAULT_ALLOW, *DEFAULT_DENY, *DEFAULT_REVIEW, *_ALIASES.values())
}
_OPERATOR_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+|[()]", re.IGNORECASE)


class LicensePolicyError(ValueError):
    """Raised when a license policy file is invalid."""


@dataclass(frozen=True)
class LicensePolicy:
    allow: frozenset[str] = frozenset(DEFAULT_ALLOW)
    deny: frozenset[str] = frozenset(DEFAULT_DENY)
    review: frozenset[str] = frozenset(DEFAULT_REVIEW)
    fail_on_unknown: bool = False
    fail_on_review: bool = False
    source: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": sorted(self.allow),
            "deny": sorted(self.deny),
            "review": sorted(self.review),
            "fail_on_unknown": self.fail_on_unknown,
            "fail_on_review": self.fail_on_review,
            "source": self.source,
        }


@dataclass(frozen=True)
class LicenseDecision:
    package: str
    ecosystem: str
    version: str
    license: str
    status: str
    reason: str
    manifest: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "license": self.license,
            "status": self.status,
            "reason": self.reason,
            "manifest": self.manifest,
            "source": self.source,
        }


@dataclass(frozen=True)
class LicenseReport:
    decisions: tuple[LicenseDecision, ...]
    policy: LicensePolicy
    warnings: tuple[str, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        counts = {"allowed": 0, "review": 0, "denied": 0, "unknown": 0}
        for decision in self.decisions:
            counts[decision.status] = counts.get(decision.status, 0) + 1
        return counts

    @property
    def failed(self) -> bool:
        counts = self.counts
        return bool(
            counts.get("denied")
            or (self.policy.fail_on_review and counts.get("review"))
            or (self.policy.fail_on_unknown and counts.get("unknown"))
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "counts": self.counts,
            "failed": self.failed,
            "warnings": list(self.warnings),
            "dependencies": [decision.to_dict() for decision in self.decisions],
        }


class _ExpressionParts:
    def __init__(self, text: str) -> None:
        self.parts: list[str] = []
        self.operators: list[str] = []
        self._parse(text)

    def _parse(self, text: str) -> None:
        tokens = [
            token.strip()
            for token in re.split(r"(\(|\)|\bAND\b|\bOR\b|\bWITH\b)", text, flags=re.IGNORECASE)
            if token and token.strip()
        ]
        for token in tokens:
            upper = token.upper()
            if token in {"(", ")"}:
                continue
            if upper in {"AND", "OR", "WITH"}:
                self.operators.append(upper)
                continue
            self.parts.append(token)

    def has_or(self) -> bool:
        return "OR" in self.operators


def normalize_license(value: str) -> str:
    text = (value or "").strip()
    if not text or text.upper() in {"NOASSERTION", "NONE", "UNKNOWN", "UNLICENSED"}:
        return UNKNOWN_LICENSE
    text = re.sub(r"\s*\+$", "-or-later", text)
    key = text.lower()
    if key in _ALIASES:
        return _ALIASES[key]
    key = re.sub(r"\s+", " ", key)
    if key in _ALIASES:
        return _ALIASES[key]
    canonical = _CANONICAL.get(key)
    if canonical is not None:
        return canonical
    return text


def _classify_one(value: str, policy: LicensePolicy) -> str:
    normalized = normalize_license(value)
    if normalized == UNKNOWN_LICENSE:
        return "unknown"
    if normalized in policy.deny:
        return "denied"
    if normalized in policy.allow:
        return "allowed"
    if normalized in policy.review:
        return "review"
    return "unknown"


def classify_license(value: str, policy: LicensePolicy) -> str:
    expression = _ExpressionParts(value)
    statuses = [_classify_one(part, policy) for part in expression.parts]
    if not statuses:
        return "unknown"
    if expression.has_or():
        if "allowed" in statuses:
            return "allowed"
        if "review" in statuses:
            return "review"
        if "unknown" in statuses:
            return "unknown"
        return "denied"
    if "denied" in statuses:
        return "denied"
    if "review" in statuses:
        return "review"
    if all(status == "allowed" for status in statuses):
        return "allowed"
    return "unknown"


def _load_policy_file(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LicensePolicyError(f"could not read license policy {path}: {exc}") from exc
    try:
        if path.suffix.lower() == ".json":
            return json.loads(raw.decode("utf-8"))
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise LicensePolicyError(f"invalid license policy {path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise LicensePolicyError(f"license policy {path} must be a table")
    section = document.get("license")
    return section if isinstance(section, Mapping) else document


def _normalized_set(values: Iterable[str]) -> frozenset[str]:
    return frozenset(
        normalize_license(str(item)) for item in values if str(item).strip()
    )


def _split_policy_string(value: str) -> list[str]:
    def known(item: str) -> bool:
        return item.lower() in _ALIASES or item.lower() in _CANONICAL

    entries: list[str] = []
    for chunk in re.split(r"[,;]+", value):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = re.split(r"\s+", chunk)
        if len(parts) > 1 and all(known(part) for part in parts):
            entries.extend(parts)
        else:
            entries.append(chunk)
    return entries


def _as_set(value: Any, *, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return _normalized_set(_split_policy_string(value))
    if isinstance(value, (list, tuple, set, frozenset)):
        return _normalized_set(str(item) for item in value)
    raise LicensePolicyError(f"license.{field_name} must be a list of strings")


def load_license_policy(
    repo_root: str | Path = ".",
    path: str | Path | None = None,
    *,
    allow: Iterable[str] = (),
    deny: Iterable[str] = (),
    review: Iterable[str] = (),
    fail_on_unknown: bool | None = None,
    fail_on_review: bool | None = None,
) -> LicensePolicy:
    root = Path(repo_root).expanduser().resolve()
    policy_path = Path(path).expanduser() if path else root / ".commit_guard.toml"
    if not policy_path.is_absolute():
        policy_path = (root / policy_path).resolve()
    defaults = LicensePolicy()
    if not policy_path.is_file() and path is not None:
        raise LicensePolicyError(f"license policy not found: {policy_path}")
    if not policy_path.is_file():
        return LicensePolicy(
            allow=frozenset(defaults.allow | _normalized_set(allow)),
            deny=frozenset(defaults.deny | _normalized_set(deny)),
            review=frozenset(defaults.review | _normalized_set(review)),
            fail_on_unknown=(
                bool(fail_on_unknown)
                if fail_on_unknown is not None
                else defaults.fail_on_unknown
            ),
            fail_on_review=(
                bool(fail_on_review)
                if fail_on_review is not None
                else defaults.fail_on_review
            ),
        )
    raw = _load_policy_file(policy_path)
    return LicensePolicy(
        allow=frozenset(
            _as_set(raw.get("allow"), field_name="allow")
            or defaults.allow
        )
        | _normalized_set(allow),
        deny=frozenset(
            _as_set(raw.get("deny"), field_name="deny") or defaults.deny
        )
        | _normalized_set(deny),
        review=frozenset(
            _as_set(raw.get("review"), field_name="review") or defaults.review
        )
        | _normalized_set(review),
        fail_on_unknown=(
            bool(raw.get("fail_on_unknown", defaults.fail_on_unknown))
            if fail_on_unknown is None
            else bool(fail_on_unknown)
        ),
        fail_on_review=(
            bool(raw.get("fail_on_review", defaults.fail_on_review))
            if fail_on_review is None
            else bool(fail_on_review)
        ),
        source=str(policy_path),
    )


def _decision(
    package: Package,
    license_entry: PackageLicense | None,
    policy: LicensePolicy,
) -> LicenseDecision:
    value = license_entry.license if license_entry else UNKNOWN_LICENSE
    status = classify_license(value, policy)
    if status == "denied":
        reason = "license is on the deny list"
    elif status == "review":
        reason = "license requires legal review"
    elif status == "allowed":
        reason = "license is on the allow list"
    else:
        reason = "license is unknown or not covered by the policy"
    return LicenseDecision(
        package=package.name,
        ecosystem=package.ecosystem,
        version=package.version,
        license=value,
        status=status,
        reason=reason,
        manifest=package.manifest,
        source=license_entry.source if license_entry else "",
    )


def evaluate_licenses(
    repo_root: str | Path,
    *,
    policy: LicensePolicy | None = None,
    packages: Iterable[Package] | None = None,
    licenses: Iterable[PackageLicense] | None = None,
) -> LicenseReport:
    root = Path(repo_root).expanduser().resolve()
    selected = policy or load_license_policy(root)
    discovered = tuple(packages if packages is not None else collect_packages(root))
    index = license_index(
        licenses if licenses is not None else collect_licenses(root)
    )
    decisions = []
    for package in discovered:
        entry = index.get(
            f"{package.ecosystem.lower()}:{normalize_name(package.name)}@{package.version}"
        )
        decisions.append(_decision(package, entry, selected))
    decisions.sort(key=lambda item: (item.status, item.package.lower(), item.version))
    return LicenseReport(decisions=tuple(decisions), policy=selected)


def format_license_report(report: LicenseReport, *, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2) + "\n"
    lines = [
        "CommitGuard dependency license report",
        f"Policy: {report.policy.source}",
        "Counts: " + ", ".join(
            f"{key}={value}" for key, value in sorted(report.counts.items())
        ),
        "",
    ]
    if not report.decisions:
        lines.append("No pinned dependencies found.")
    else:
        lines.append("STATUS   LICENSE                 PACKAGE")
        for decision in report.decisions:
            lines.append(
                f"{decision.status:<8} {decision.license[:23]:<23} "
                f"{decision.package} {decision.version}"
            )
    if report.failed:
        lines.append("")
        lines.append("License policy: FAILED")
    else:
        lines.append("")
        lines.append("License policy: PASSED")
    return "\n".join(lines) + "\n"
