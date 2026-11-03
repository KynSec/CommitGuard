"""Determinant scan profiles and file/rule selection.

Profiles live in ``rules/scan_profiles.yaml`` and are intentionally small,
human-editable selections rather than a second rules format.  A profile can
choose the scan mode, include/exclude paths (files or directories), and limit
the active rules by source, id pattern, or severity.

CLI flags always override profile values.  Path exclusions are additive so a
profile can exclude generated code without discarding the built-in safety
exclusions or ``.commit_guard.toml`` exclusions.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dependency is declared
    raise ImportError(
        "PyYAML is required to parse scan profiles. Install it with: pip install pyyaml"
    ) from exc

from core.paths import PathMatcher
from core.rule_loader import SEVERITY_ORDER, RuleSet

PROFILE_FILENAME = "scan_profiles.yaml"
PROFILE_DOC_FILENAME = "SCAN_PROFILES.md"
VALID_PROFILE_MODES = ("inherit", "staged", "repo")
VALID_RULE_SEVERITIES = tuple(SEVERITY_ORDER)
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ProfileError(RuntimeError):
    """Raised when a scan profile file is malformed or a profile is missing."""


def _as_tuple(value: object, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(item.strip() for item in value if item.strip())
    raise ProfileError(f"'{key}' must be a string or a list of strings.")


def _string_list(value: object, key: str) -> tuple[str, ...]:
    items = _as_tuple(value, key)
    for item in items:
        if "\n" in item or "\r" in item or "\x00" in item or item.startswith("-"):
            raise ProfileError(f"Invalid value in '{key}': {item!r}")
    return items


def _table(value: object, key: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"'{key}' must be a table.")
    return value


@dataclass(frozen=True)
class ScanProfile:
    """A named, deterministic selection of scan mode, paths, and rules."""

    name: str
    description: str = ""
    mode: str = "inherit"
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    rule_sources: tuple[str, ...] = ()
    include_rules: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    rule_severities: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "paths": {"include": list(self.include), "exclude": list(self.exclude)},
            "rules": {
                "sources": list(self.rule_sources),
                "include": list(self.include_rules),
                "exclude": list(self.exclude_rules),
                "severities": list(self.rule_severities),
            },
        }


@dataclass(frozen=True)
class RuleSelection:
    """Filters rules by source, id glob, and severity."""

    sources: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        return bool(self.sources or self.include or self.exclude or self.severities)

    def matches_source(self, source: str) -> bool:
        if not self.sources:
            return True
        return any(source == item or source.startswith(item + ":") for item in self.sources)

    def matches(self, rule_id: str, source: str, severity: str) -> bool:
        if not self.matches_source(source):
            return False
        if self.severities and severity not in self.severities:
            return False
        if self.include and not any(
            fnmatch.fnmatchcase(rule_id, pattern) for pattern in self.include
        ):
            return False
        return not any(
            fnmatch.fnmatchcase(rule_id, pattern) for pattern in self.exclude
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "sources": list(self.sources),
            "include": list(self.include),
            "exclude": list(self.exclude),
            "severities": list(self.severities),
        }


class PathSelection:
    """Applies include-first and exclude-last path matching."""

    def __init__(
        self,
        include: Iterable[str] = (),
        exclude: Iterable[str] = (),
    ) -> None:
        self.include = tuple(include)
        self.exclude = tuple(exclude)
        self._includes = PathMatcher(self.include) if self.include else None
        self._excludes = PathMatcher(self.exclude) if self.exclude else None

    def matches(self, path: str | Path) -> bool:
        if self._includes is not None and not self._includes.matches(path):
            return False
        return not (self._excludes is not None and self._excludes.matches(path))


@dataclass(frozen=True)
class ScanSelection:
    """The fully merged selection used by one scan."""

    profile: ScanProfile | None = None
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    rules: RuleSelection = field(default_factory=RuleSelection)

    @property
    def paths(self) -> PathSelection:
        return PathSelection(self.include, self.exclude)

    @property
    def active(self) -> bool:
        return bool(
            self.profile
            or self.include
            or self.rules.active
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile.name if self.profile else None,
            "paths": {
                "include": list(self.include),
                "exclude": list(self.exclude),
            },
            "rules": self.rules.to_dict(),
        }


def load_scan_profiles(
    rules_dir: Path,
    explicit_path: Path | None = None,
) -> dict[str, ScanProfile]:
    """Loads ``rules/scan_profiles.yaml``; a missing file means no profiles."""
    path = explicit_path or (rules_dir / PROFILE_FILENAME)
    if not path.is_file():
        if explicit_path is not None:
            raise ProfileError(f"Scan profile file not found: {path}")
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileError(f"Could not parse {path}: {exc}") from exc
    except OSError as exc:
        raise ProfileError(f"Could not read {path}: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError(f"{path} must contain a mapping of profiles.")
    raw_profiles = raw.get("profiles", raw)
    if not isinstance(raw_profiles, dict):
        raise ProfileError(f"'profiles' in {path} must be a table.")

    profiles: dict[str, ScanProfile] = {}
    for raw_name, entry in raw_profiles.items():
        name = str(raw_name).strip()
        if not _PROFILE_NAME_RE.match(name):
            raise ProfileError(f"Invalid profile name '{name}' in {path}.")
        if not isinstance(entry, dict):
            raise ProfileError(f"Profile '{name}' in {path} must be a table.")
        paths = _table(entry.get("paths"), f"profiles.{name}.paths")
        rules = _table(entry.get("rules"), f"profiles.{name}.rules")
        mode = str(entry.get("mode", "inherit")).strip().lower()
        if mode not in VALID_PROFILE_MODES:
            raise ProfileError(
                f"Invalid mode '{mode}' in profile '{name}'. "
                f"Choose one of: {', '.join(VALID_PROFILE_MODES)}."
            )
        severities = _string_list(
            rules.get("severities"), f"profiles.{name}.rules.severities"
        )
        for severity in severities:
            if severity not in VALID_RULE_SEVERITIES:
                raise ProfileError(
                    f"Invalid severity '{severity}' in profile '{name}'. "
                    f"Choose one of: {', '.join(VALID_RULE_SEVERITIES)}."
                )
        profiles[name] = ScanProfile(
            name=name,
            description=str(entry.get("description", "")).strip(),
            mode=mode,
            include=_string_list(paths.get("include"), f"profiles.{name}.paths.include"),
            exclude=_string_list(paths.get("exclude"), f"profiles.{name}.paths.exclude"),
            rule_sources=_string_list(
                rules.get("sources"), f"profiles.{name}.rules.sources"
            ),
            include_rules=_string_list(
                rules.get("include"), f"profiles.{name}.rules.include"
            ),
            exclude_rules=_string_list(
                rules.get("exclude"), f"profiles.{name}.rules.exclude"
            ),
            rule_severities=severities,
        )
    return profiles


def resolve_profile(profiles: dict[str, ScanProfile], name: str | None) -> ScanProfile | None:
    if not name:
        return None
    if name in profiles:
        return profiles[name]
    if name == "default":
        return ScanProfile(name="default")
    available = ", ".join(sorted(profiles)) or "(none)"
    raise ProfileError(
        f"Unknown scan profile '{name}'. Available profiles: {available}."
    )


def merge_selection(
    profile: ScanProfile | None,
    *,
    include: Iterable[str] = (),
    exclude: Iterable[str] = (),
    rule_sources: Iterable[str] = (),
    include_rules: Iterable[str] = (),
    exclude_rules: Iterable[str] = (),
    rule_severities: Iterable[str] = (),
) -> ScanSelection:
    """Merges profile defaults with explicit overrides.

    Includes and rule sources replace profile values when supplied. Excludes
    are additive so callers can keep built-in safety exclusions.
    """
    cli_include = tuple(include)
    cli_exclude = tuple(exclude)
    cli_sources = tuple(rule_sources)
    cli_include_rules = tuple(include_rules)
    cli_exclude_rules = tuple(exclude_rules)
    cli_severities = tuple(rule_severities)
    return ScanSelection(
        profile=profile,
        include=cli_include or (profile.include if profile else ()),
        exclude=(profile.exclude if profile else ()) + cli_exclude,
        rules=RuleSelection(
            sources=cli_sources or (profile.rule_sources if profile else ()),
            include=cli_include_rules or (profile.include_rules if profile else ()),
            exclude=(profile.exclude_rules if profile else ()) + cli_exclude_rules,
            severities=cli_severities or (profile.rule_severities if profile else ()),
        ),
    )


def filter_ruleset(ruleset: RuleSet, selection: RuleSelection) -> RuleSet:
    if not selection.active:
        return ruleset
    return RuleSet(
        rules=tuple(
            rule
            for rule in ruleset.rules
            if selection.matches(rule.rule_id, rule.source, rule.severity)
        ),
        skipped=ruleset.skipped,
        path_allowlist=ruleset.path_allowlist,
        line_allowlist=ruleset.line_allowlist,
    )


def ast_rule_source(rule_id: str) -> str:
    return "javascript_ast" if "js-ast" in rule_id else "python_ast"


def selected_ast_rule_ids(selection: RuleSelection) -> frozenset[str] | None:
    """Returns selected taint rule ids, or None when no rule filtering is active."""
    if not selection.active:
        return None
    from core.ast_taint import TAINT_RULES

    return frozenset(
        rule_id
        for rule_id, details in TAINT_RULES.items()
        if selection.matches(
            rule_id,
            ast_rule_source(rule_id),
            str(details.get("severity", "medium")),
        )
    )


def scan_profiles_doc_text() -> str:
    """Returns the bundled user guide, including from a wheel or zipapp."""
    try:
        return (
            resources.files("commit_guard_docs")
            .joinpath(PROFILE_DOC_FILENAME)
            .read_text(encoding="utf-8")
        )
    except (ImportError, ModuleNotFoundError, FileNotFoundError, OSError):
        fallback = Path(__file__).resolve().parent.parent / "docs" / PROFILE_DOC_FILENAME
        try:
            return fallback.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileError(f"Could not read scan profile documentation: {exc}") from exc
