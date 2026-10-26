"""Policy v1: deterministic new-code gate, budgets, ratchet, and explain."""

from __future__ import annotations

import fnmatch
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

from core import __version__
from core.findings import CATEGORIES, SEVERITIES
from core.rule_loader import SEVERITY_ORDER
from core.scanner import Finding

PROFILES = ("strict", "balanced", "audit")
FAIL_ON = ("all", "new")
_KNOWN_GATE_KEYS = {
    "profile",
    "fail_on",
    "threshold",
    "ratchet",
    "max_new",
    "budgets",
    "allow_expired_triage",
    "enforce",
}


class PolicyError(ValueError):
    """Raised for invalid or unreadable policy configuration."""


@dataclass(frozen=True)
class Policy:
    profile: str = "balanced"
    fail_on: str = "new"
    threshold: str = "high"
    ratchet: bool = True
    max_new: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 25, "low": 100}
    )
    path_budgets: dict[str, dict[str, int]] = field(default_factory=dict)
    category_budgets: dict[str, dict[str, int]] = field(default_factory=dict)
    allow_expired_triage: bool = False
    enforce: bool = True
    source: str = "defaults"

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "fail_on": self.fail_on,
            "threshold": self.threshold,
            "ratchet": self.ratchet,
            "max_new": dict(self.max_new),
            "budgets": {
                "paths": {k: dict(v) for k, v in self.path_budgets.items()},
                "categories": {
                    k: dict(v) for k, v in self.category_budgets.items()
                },
            },
            "allow_expired_triage": self.allow_expired_triage,
            "enforce": self.enforce,
            "source": self.source,
        }


def _profile_defaults(profile: str) -> Policy:
    if profile == "strict":
        return Policy(
            profile="strict",
            fail_on="all",
            threshold="medium",
            ratchet=True,
            max_new={
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            allow_expired_triage=False,
            enforce=True,
        )
    if profile == "balanced":
        return Policy()
    if profile == "audit":
        return Policy(
            profile="audit",
            fail_on="new",
            threshold="info",
            ratchet=False,
            max_new={},
            allow_expired_triage=True,
            enforce=False,
        )
    raise PolicyError(f"unknown policy profile: {profile!r}")


def _positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"gate.{key} must be a non-negative integer")
    return value


def _severity_budget(raw: Any, key: str) -> dict[str, int]:
    if not isinstance(raw, Mapping):
        raise PolicyError(f"gate.{key} must be a table of severity counts")
    result: dict[str, int] = {}
    for severity, count in raw.items():
        if severity not in SEVERITIES:
            raise PolicyError(
                f"gate.{key}: unknown severity {severity!r}; "
                f"expected one of {', '.join(SEVERITIES)}"
            )
        result[str(severity)] = _positive_int(count, f"{key}.{severity}")
    return result


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise PolicyError(f"could not read policy file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy file {path} must contain a TOML table")
    return data


def load_policy(
    repo_root: str | Path,
    path: str | Path | None = None,
    *,
    profile: str | None = None,
    threshold: str | None = None,
) -> Policy:
    """Loads ``[gate]`` from a TOML file or returns the selected profile."""
    root = Path(repo_root).expanduser().resolve()
    explicit = Path(path).expanduser() if path is not None else None
    if explicit is not None and not explicit.is_absolute():
        explicit = (root / explicit).resolve()
    config_path = explicit or (root / ".commit_guard.toml")
    raw: dict[str, Any] = {}
    source = "defaults"
    if config_path.is_file():
        raw = _load_toml(config_path)
        source = str(config_path)
    elif explicit is not None:
        raise PolicyError(f"policy file not found: {config_path}")
    gate = raw.get("gate", {})
    if gate is None:
        gate = {}
    if not isinstance(gate, Mapping):
        raise PolicyError("[gate] must be a TOML table")
    unknown = set(gate) - _KNOWN_GATE_KEYS
    if unknown:
        raise PolicyError(
            "[gate] contains unknown key(s): " + ", ".join(sorted(unknown))
        )
    threshold_override = threshold
    selected_profile = str(profile or gate.get("profile") or "balanced")
    policy = _profile_defaults(selected_profile)
    updates: dict[str, Any] = {"source": source}
    if "fail_on" in gate:
        fail_on = str(gate["fail_on"])
        if fail_on not in FAIL_ON:
            raise PolicyError("gate.fail_on must be 'all' or 'new'")
        updates["fail_on"] = fail_on
    if "threshold" in gate:
        threshold = str(gate["threshold"]).lower()
        if threshold not in SEVERITIES:
            raise PolicyError(
                "gate.threshold must be one of " + ", ".join(SEVERITIES)
            )
        updates["threshold"] = threshold
    if "ratchet" in gate:
        if not isinstance(gate["ratchet"], bool):
            raise PolicyError("gate.ratchet must be a boolean")
        updates["ratchet"] = gate["ratchet"]
    if "allow_expired_triage" in gate:
        if not isinstance(gate["allow_expired_triage"], bool):
            raise PolicyError("gate.allow_expired_triage must be a boolean")
        updates["allow_expired_triage"] = gate["allow_expired_triage"]
    if "enforce" in gate:
        if not isinstance(gate["enforce"], bool):
            raise PolicyError("gate.enforce must be a boolean")
        updates["enforce"] = gate["enforce"]
    if "max_new" in gate:
        updates["max_new"] = _severity_budget(gate["max_new"], "max_new")
    if threshold_override is not None:
        override = str(threshold_override).lower()
        if override not in SEVERITIES:
            raise PolicyError(
                "threshold must be one of " + ", ".join(SEVERITIES)
            )
        updates["threshold"] = override
    if "budgets" in gate:
        budgets = gate["budgets"]
        if not isinstance(budgets, Mapping):
            raise PolicyError("gate.budgets must be a TOML table")
        path_budgets: dict[str, dict[str, int]] = {}
        category_budgets: dict[str, dict[str, int]] = {}
        for key, value in budgets.items():
            name = str(key)
            parsed = _severity_budget(value, f"budgets.{name}")
            if name in CATEGORIES or not any(char in name for char in "/*?[."):
                category_budgets[name] = parsed
            else:
                path_budgets[name] = parsed
        updates["path_budgets"] = path_budgets
        updates["category_budgets"] = category_budgets
    return replace(policy, **updates)


def _is_new(finding: Finding, baseline_fingerprints: set[str]) -> bool:
    if finding.baseline_state == "unchanged":
        return False
    return finding.fingerprint not in baseline_fingerprints


def _reason(
    finding: Finding, reason: str, *, rule_id: str | None = None
) -> dict[str, Any]:
    return {
        "rule_id": rule_id or finding.rule_id,
        "path": finding.file,
        "line": finding.line_number,
        "fingerprint": finding.fingerprint,
        "reason": reason,
    }


@dataclass(frozen=True)
class GateResult:
    passed: bool
    profile: str
    threshold: str
    fail_on: str
    new_findings: int
    blocking: int
    total: int
    reasons: tuple[dict[str, Any], ...] = ()
    budgets: dict[str, Any] = field(default_factory=dict)
    suppressed: dict[str, int] = field(default_factory=dict)
    tool_versions: dict[str, str] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "passed": self.passed,
            "profile": self.profile,
            "threshold": self.threshold,
            "fail_on": self.fail_on,
            "new_findings": self.new_findings,
            "blocking": self.blocking,
            "total": self.total,
            "reasons": list(self.reasons),
            "budgets": self.budgets,
            "suppressed": dict(self.suppressed),
            "tool_versions": dict(self.tool_versions),
        }


def _count_by(items: Iterable[Finding], key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = key(item)
        counts[value] = counts.get(value, 0) + 1
    return counts


def evaluate_gate(
    findings: Iterable[Finding],
    policy: Policy,
    *,
    baseline_fingerprints: Iterable[str] = (),
    suppressed: Mapping[str, int] | None = None,
    tool_versions: Mapping[str, str] | None = None,
    baseline_count: int | None = None,
) -> GateResult:
    baseline = set(baseline_fingerprints)
    items = list(findings)
    new_items = [finding for finding in items if _is_new(finding, baseline)]
    threshold_rank = SEVERITY_ORDER.get(policy.threshold, SEVERITY_ORDER["high"])
    reasons: list[dict[str, Any]] = []
    blocking: set[str] = set()

    def add(finding: Finding, text: str) -> None:
        reasons.append(_reason(finding, text))
        blocking.add(finding.fingerprint)

    for finding in items:
        is_new = _is_new(finding, baseline)
        provenance = finding.provenance or {}
        if provenance.get("triage_expired"):
            if not policy.allow_expired_triage:
                add(finding, "expired triage exception")
            continue
        if provenance.get("triage_fixed_still_present"):
            add(finding, "finding marked fixed is still present")
            continue
        if policy.fail_on == "new" and not is_new:
            continue
        if not finding.blocking:
            continue
        if SEVERITY_ORDER.get(finding.severity, 0) >= threshold_rank:
            label = "new" if is_new else "existing"
            add(finding, f"{label} {finding.severity} finding")

    new_by_severity = _count_by(new_items, lambda finding: finding.severity)
    for severity in SEVERITIES:
        limit = policy.max_new.get(severity)
        count = new_by_severity.get(severity, 0)
        if limit is not None and count > limit:
            synthetic = next(
                finding for finding in new_items if finding.severity == severity
            )
            reasons.append(
                _reason(
                    synthetic,
                    f"new {severity} budget exceeded: {count} > {limit}",
                    rule_id="policy/budget/severity",
                )
            )
    for pattern, limits in sorted(policy.path_budgets.items()):
        matching = [
            finding
            for finding in new_items
            if fnmatch.fnmatch(finding.file, pattern)
        ]
        by_severity = _count_by(matching, lambda finding: finding.severity)
        for severity, limit in sorted(limits.items()):
            count = by_severity.get(severity, 0)
            if count > limit and matching:
                synthetic = next(
                    finding
                    for finding in matching
                    if finding.severity == severity
                )
                reasons.append(
                    _reason(
                        synthetic,
                        f"new {severity} budget for {pattern} exceeded: "
                        f"{count} > {limit}",
                        rule_id="policy/budget/path",
                    )
                )
    for category, limits in sorted(policy.category_budgets.items()):
        matching = [
            finding
            for finding in new_items
            if finding.category == category
            or category in finding.tags
            or (category == "python" and finding.file.lower().endswith((".py", ".pyi")))
        ]
        by_severity = _count_by(matching, lambda finding: finding.severity)
        for severity, limit in sorted(limits.items()):
            count = by_severity.get(severity, 0)
            if count > limit and matching:
                synthetic = next(
                    finding
                    for finding in matching
                    if finding.severity == severity
                )
                reasons.append(
                    _reason(
                        synthetic,
                        f"new {severity} budget for category {category} "
                        f"exceeded: {count} > {limit}",
                        rule_id="policy/budget/category",
                    )
                )
    above_threshold = [
        finding
        for finding in new_items
        if SEVERITY_ORDER.get(finding.severity, 0) >= threshold_rank
    ]
    if policy.ratchet and above_threshold:
        reasons.append(
            {
                "rule_id": "policy/ratchet",
                "path": "",
                "line": 0,
                "fingerprint": "",
                "reason": (
                    f"ratchet: {len(above_threshold)} new finding(s) at or above "
                    f"{policy.threshold}"
                ),
            }
        )
    if (
        policy.ratchet
        and baseline_count is not None
        and len(items) > baseline_count
        and new_items
    ):
        reasons.append(
            {
                "rule_id": "policy/ratchet/total",
                "path": "",
                "line": 0,
                "fingerprint": "",
                "reason": (
                    f"ratchet: total findings grew from {baseline_count} "
                    f"to {len(items)}"
                ),
            }
        )
    versions = {"commit-guard": __version__}
    if tool_versions:
        versions.update({str(key): str(value) for key, value in tool_versions.items()})
    if not policy.enforce:
        reasons = []
    return GateResult(
        passed=not reasons,
        profile=policy.profile,
        threshold=policy.threshold,
        fail_on=policy.fail_on,
        new_findings=len(new_items),
        blocking=len(blocking),
        total=len(items),
        reasons=tuple(reasons),
        budgets={
            "max_new": dict(policy.max_new),
            "paths": {k: dict(v) for k, v in policy.path_budgets.items()},
            "categories": {
                k: dict(v) for k, v in policy.category_budgets.items()
            },
        },
        suppressed=dict(suppressed or {}),
        tool_versions=versions,
    )


def explain_finding(
    finding: Finding,
    policy: Policy,
    *,
    baseline_fingerprints: Iterable[str] = (),
    triage_state: str | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    baseline = set(baseline_fingerprints)
    chain: list[dict[str, Any]] = []
    chain.append(
        {
            "stage": "inline",
            "outcome": "not-evaluated",
            "detail": "inline directives are applied before the report is built",
        }
    )
    if triage_state:
        chain.append(
            {
                "stage": "triage",
                "outcome": "suppressed" if triage_state in {"accepted", "false_positive", "wont_fix"} else triage_state,
                "detail": f"triage state: {triage_state}",
            }
        )
    else:
        chain.append(
            {"stage": "triage", "outcome": "none", "detail": "no triage entry"}
        )
    is_new = _is_new(finding, baseline)
    chain.append(
        {
            "stage": "baseline",
            "outcome": "new" if is_new else "unchanged",
            "detail": (
                "fingerprint absent from baseline"
                if is_new
                else "fingerprint present in baseline"
            ),
        }
    )
    threshold_rank = SEVERITY_ORDER.get(policy.threshold, SEVERITY_ORDER["high"])
    severity_blocks = SEVERITY_ORDER.get(finding.severity, 0) >= threshold_rank
    chain.append(
        {
            "stage": "severity",
            "outcome": "above-threshold" if severity_blocks else "below-threshold",
            "detail": f"{finding.severity} vs threshold {policy.threshold}",
        }
    )
    gate_blocks = finding.blocking and severity_blocks and (
        is_new or policy.fail_on == "all"
    )
    chain.append(
        {
            "stage": "gate",
            "outcome": "blocking" if gate_blocks else "passing",
            "detail": (
                f"fail_on={policy.fail_on}; finding is "
                f"{'new' if is_new else 'existing'}"
            ),
        }
    )
    result = evaluate_gate(
        [finding],
        policy,
        baseline_fingerprints=baseline,
        suppressed={},
    )
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "path": finding.file,
        "line": finding.line_number,
        "profile": policy.profile,
        "chain": chain,
        "gate": result.to_dict(),
        "today": (today or date.today()).isoformat(),
    }
