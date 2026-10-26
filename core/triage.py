"""Committed triage state (``.commit_guard/triage.yaml``)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from core.scanner import Finding

TRIAGE_VERSION = 1
TRIAGE_STATES = ("accepted", "false_positive", "wont_fix", "fixed")
SUPPRESSING_STATES = {"accepted", "false_positive", "wont_fix"}
DEFAULT_TRIAGE_PATH = Path(".commit_guard/triage.yaml")


class TriageError(ValueError):
    """Raised for invalid or conflicting triage data."""


@dataclass(frozen=True)
class TriageEntry:
    fingerprint: str
    state: str
    rule_id: str = ""
    path: str = ""
    owner: str = ""
    reason: str = ""
    ticket: str = ""
    expires: str = ""
    created: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "path": self.path,
            "state": self.state,
            "owner": self.owner,
            "reason": self.reason,
            "ticket": self.ticket,
            "expires": self.expires,
            "created": self.created,
            "evidence": self.evidence,
        }
        payload.update(self.metadata)
        return {key: value for key, value in payload.items() if value not in ("", None, {})}

    def expired(self, today: date | None = None) -> bool:
        if not self.expires:
            return False
        try:
            expiry = date.fromisoformat(self.expires)
        except ValueError:
            return True
        return expiry < (today or date.today())


@dataclass(frozen=True)
class TriageState:
    entries: tuple[TriageEntry, ...] = ()
    path: Path | None = None
    version: int = TRIAGE_VERSION

    def by_fingerprint(self) -> dict[str, TriageEntry]:
        return {entry.fingerprint: entry for entry in self.entries}

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _entry_from_dict(raw: Mapping[str, Any], index: int) -> TriageEntry:
    if not isinstance(raw, Mapping):
        raise TriageError(f"triage entry {index} must be an object")
    fingerprint = str(raw.get("fingerprint") or "").strip()
    if not fingerprint:
        raise TriageError(f"triage entry {index} is missing fingerprint")
    state = str(raw.get("state") or "").strip()
    if state not in TRIAGE_STATES:
        raise TriageError(
            f"triage entry {fingerprint} has invalid state {state!r}"
        )
    known = {
        "fingerprint",
        "state",
        "rule_id",
        "path",
        "owner",
        "reason",
        "ticket",
        "expires",
        "created",
        "evidence",
    }
    metadata = {key: value for key, value in raw.items() if key not in known}
    entry = TriageEntry(
        fingerprint=fingerprint,
        state=state,
        rule_id=str(raw.get("rule_id") or ""),
        path=str(raw.get("path") or ""),
        owner=str(raw.get("owner") or ""),
        reason=str(raw.get("reason") or ""),
        ticket=str(raw.get("ticket") or ""),
        expires=str(raw.get("expires") or ""),
        created=str(raw.get("created") or ""),
        evidence=str(raw.get("evidence") or ""),
        metadata=metadata,
    )
    validate_entry(entry)
    return entry


def validate_entry(entry: TriageEntry) -> None:
    if entry.state in SUPPRESSING_STATES:
        if not entry.owner:
            raise TriageError(
                f"triage entry {entry.fingerprint} requires an owner"
            )
        if not entry.reason:
            raise TriageError(
                f"triage entry {entry.fingerprint} requires a reason"
            )
    if entry.expires:
        try:
            date.fromisoformat(entry.expires)
        except ValueError as exc:
            raise TriageError(
                f"triage entry {entry.fingerprint} has invalid expiry; "
                "use YYYY-MM-DD"
            ) from exc


def triage_path(repo_root: str | Path, path: str | Path | None = None) -> Path:
    root = Path(repo_root).expanduser().resolve()
    candidate = Path(path).expanduser() if path is not None else DEFAULT_TRIAGE_PATH
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate


def load_triage(
    repo_root: str | Path, path: str | Path | None = None
) -> TriageState:
    resolved = triage_path(repo_root, path)
    if not resolved.is_file():
        return TriageState(path=resolved)
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TriageError(f"could not read triage file {resolved}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise TriageError(f"invalid YAML in {resolved}: {exc}") from exc
    if raw is None:
        return TriageState(path=resolved)
    if not isinstance(raw, Mapping):
        raise TriageError("triage file must be a mapping")
    version = raw.get("version", TRIAGE_VERSION)
    if version != TRIAGE_VERSION:
        raise TriageError(
            f"unsupported triage version {version}; expected {TRIAGE_VERSION}"
        )
    entries_raw = raw.get("entries", [])
    if not isinstance(entries_raw, list):
        raise TriageError("triage entries must be a list")
    entries: dict[str, TriageEntry] = {}
    for index, item in enumerate(entries_raw):
        entry = _entry_from_dict(item, index)
        existing = entries.get(entry.fingerprint)
        if existing is not None and existing.state != entry.state:
            raise TriageError(
                f"conflicting triage states for fingerprint {entry.fingerprint}"
            )
        entries[entry.fingerprint] = entry
    return TriageState(
        entries=tuple(entries[key] for key in sorted(entries)),
        path=resolved,
        version=version,
    )


def save_triage(state: TriageState, path: str | Path | None = None) -> Path:
    target = Path(path) if path is not None else state.path
    if target is None:
        raise TriageError("triage path is required")
    target = target.expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        state.to_dict(), sort_keys=False, allow_unicode=False, default_flow_style=False
    )
    target.write_text(
        "# Commit Guard triage state. Review changes like code.\n" + text,
        encoding="utf-8",
    )
    return target


def set_entry(
    state: TriageState,
    *,
    fingerprint: str,
    triage_state: str,
    owner: str = "",
    reason: str = "",
    rule_id: str = "",
    path: str = "",
    ticket: str = "",
    expires: str = "",
    evidence: str = "",
    created: str | None = None,
) -> TriageState:
    if triage_state not in TRIAGE_STATES:
        raise TriageError(f"invalid triage state: {triage_state!r}")
    entry = TriageEntry(
        fingerprint=fingerprint,
        state=triage_state,
        rule_id=rule_id,
        path=path,
        owner=owner,
        reason=reason,
        ticket=ticket,
        expires=expires,
        created=created or date.today().isoformat(),
        evidence=evidence,
    )
    validate_entry(entry)
    entries = {item.fingerprint: item for item in state.entries}
    previous = entries.get(fingerprint)
    if previous is not None:
        entry = replace(
            entry,
            created=previous.created or entry.created,
            rule_id=entry.rule_id or previous.rule_id,
            path=entry.path or previous.path,
        )
    entries[fingerprint] = entry
    return replace(
        state,
        entries=tuple(entries[key] for key in sorted(entries)),
    )


@dataclass(frozen=True)
class TriageApplication:
    visible: tuple[Finding, ...]
    suppressed: dict[str, int]
    expired: tuple[TriageEntry, ...] = ()
    fixed_still_present: tuple[TriageEntry, ...] = ()

    @property
    def suppressed_total(self) -> int:
        return sum(self.suppressed.values())


def apply_triage(
    findings: Iterable[Finding],
    state: TriageState,
    *,
    today: date | None = None,
) -> TriageApplication:
    entries = state.by_fingerprint()
    today = today or date.today()
    visible: list[Finding] = []
    suppressed = {"triage": 0}
    expired: list[TriageEntry] = []
    fixed_present: list[TriageEntry] = []
    for finding in findings:
        entry = entries.get(finding.fingerprint)
        if entry is None:
            visible.append(finding)
            continue
        if entry.state in SUPPRESSING_STATES:
            if entry.expired(today):
                expired.append(entry)
                visible.append(
                    replace(
                        finding,
                        provenance={
                            **(finding.provenance or {}),
                            "triage_expired": True,
                            "triage_entry": entry.to_dict(),
                        },
                    )
                )
            else:
                suppressed["triage"] = suppressed.get("triage", 0) + 1
            continue
        if entry.state == "fixed":
            fixed_present.append(entry)
            visible.append(
                replace(
                    finding,
                    provenance={
                        **(finding.provenance or {}),
                        "triage_fixed_still_present": True,
                        "triage_entry": entry.to_dict(),
                    },
                )
            )
            continue
        visible.append(finding)
    return TriageApplication(
        visible=tuple(visible),
        suppressed=suppressed,
        expired=tuple(expired),
        fixed_still_present=tuple(fixed_present),
    )


def prune_triage(
    state: TriageState,
    present_fingerprints: Iterable[str],
    *,
    dry_run: bool = False,
) -> tuple[TriageState, tuple[str, ...]]:
    present = set(present_fingerprints)
    removed = tuple(
        entry.fingerprint
        for entry in state.entries
        if entry.state == "fixed" and entry.fingerprint not in present
    )
    if dry_run or not removed:
        return state, removed
    removed_set = set(removed)
    return (
        replace(
            state,
            entries=tuple(
                entry
                for entry in state.entries
                if entry.fingerprint not in removed_set
            ),
        ),
        removed,
    )


def audit_triage(
    state: TriageState,
    present_fingerprints: Iterable[str],
    *,
    today: date | None = None,
) -> list[str]:
    present = set(present_fingerprints)
    today = today or date.today()
    issues: list[str] = []
    for entry in state.entries:
        if entry.expired(today):
            issues.append(
                f"{entry.fingerprint}: expired {entry.expires} ({entry.state})"
            )
        if entry.fingerprint not in present:
            issues.append(
                f"{entry.fingerprint}: no current finding ({entry.state})"
            )
        if entry.state == "fixed" and entry.fingerprint in present:
            issues.append(
                f"{entry.fingerprint}: marked fixed but still present"
            )
        if entry.state in SUPPRESSING_STATES and not entry.ticket:
            issues.append(f"{entry.fingerprint}: suppression has no ticket")
        if entry.state in SUPPRESSING_STATES and not entry.expires:
            issues.append(f"{entry.fingerprint}: suppression has no expiry")
    return issues
