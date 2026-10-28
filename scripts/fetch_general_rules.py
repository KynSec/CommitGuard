#!/usr/bin/env python3
"""Download and normalize Microsoft DevSkim's default rule pack.

DevSkim publishes its rules as JSON under ``rules/default``.  CommitGuard's
native rule format is intentionally small, so this script converts the
regex-compatible subset into grouped YAML packs under
``rules/general/devskim``.

The upstream project is MIT-licensed.  Rules that depend on DevSkim's
structured analyzers (xpath/ymlpath conditions, boolean expressions, or
language exclusions) are skipped rather than approximated unsafely.  The
script is deterministic: re-running it against the pinned revision produces
the same files.

Usage:
    python scripts/fetch_general_rules.py
    python scripts/fetch_general_rules.py --revision <commit> --dry-run
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

DEVSKIM_REPOSITORY = "microsoft/DevSkim"
DEVSKIM_REVISION = "bd81f6967d84b3ef1dbce9e466dc28e124f56289"
DEVSKIM_TARBALL = (
    f"https://codeload.github.com/{DEVSKIM_REPOSITORY}/tar.gz/{DEVSKIM_REVISION}"
)
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "rules" / "general" / "devskim"

_GROUPS = (
    ("api", ("security/api", "security/control_flow", "security/manualreview")),
    ("crypto", ("security/cryptography",)),
    ("web", ("security/web", "security/xml", "security/attack_surface")),
    (
        "platform",
        (
            "security/frameworks",
            "security/containers",
            "security/storage",
            "security/privacy",
            "security/hygiene",
        ),
    ),
    ("supplychain", ("security/supplychain", "security/vulnerable_libraries")),
    ("tls", ("security/TLS",)),
    ("correctness", ("correctness",)),
)

_SEVERITY = {
    "critical": "critical",
    "important": "high",
    "moderate": "medium",
    "manualreview": "medium",
    "bestpractice": "low",
    "informational": "info",
}

_CONFIDENCE = {
    "critical": "high",
    "important": "high",
    "moderate": "medium",
    "manualreview": "low",
    "bestpractice": "low",
    "informational": "low",
}

_GROUP_CATEGORY = {
    "api": "sast",
    "crypto": "sast",
    "web": "web",
    "platform": "sast",
    "supplychain": "supply-chain",
    "tls": "sast",
    "correctness": "quality",
}

# DevSkim language names that are not already in the loader's Semgrep map.
_LANGUAGES = {
    "batch": "batch",
    ".config": "config",
    "cobol": "cobol",
    "csharp project": "csproj",
    "dotenv": "dotenv",
    "fsharp": "fsharp",
    "javascriptreact": "javascriptreact",
    "objective-c": "objective-c",
    "packages.config": "packages-config",
    "pip-config": "pip-config",
    "pip-requirements": "pip-requirements",
    "powershell": "powershell",
    "razor": "razor",
    "shellscript": "shellscript",
    "sql": "sql",
    "typescriptreact": "typescriptreact",
    "vb": "vb",
}

_SECRET_TAG_MARKERS = (
    "secret",
    "credential",
    "password",
    "token",
    "privatekey",
    "private_key",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "storagekey",
    "storage_key",
)
_SECRET_TEXT_MARKERS = (
    "private key",
    "access token",
    "api key",
    "credential",
    "password",
    "storage account key",
    "secret",
)

_SAFE_MODIFIERS = set("imsx")
_INCOMPATIBLE_MARKERS = ("(?>", "(?(", "\\p{", "\\P{", "\\k<")


class RuleConversionError(ValueError):
    """Raised when a DevSkim rule cannot be represented safely."""


def _download_repository(revision: str) -> dict[str, list[dict[str, Any]]]:
    url = (
        f"https://codeload.github.com/{DEVSKIM_REPOSITORY}/tar.gz/{revision}"
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "CommitGuard-rule-updater"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        archive = response.read()

    rules: dict[str, list[dict[str, Any]]] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if len(parts) < 3 or parts[0] != f"DevSkim-{revision}":
                continue
            relative = Path(*parts[1:]).as_posix()
            if not relative.startswith("rules/default/") or not relative.endswith(
                ".json"
            ):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                payload = json.loads(handle.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuleConversionError(f"{relative}: invalid JSON ({exc})") from exc
            if not isinstance(payload, list):
                raise RuleConversionError(f"{relative}: expected a rule list")
            rules[relative.removeprefix("rules/default/")] = [
                entry for entry in payload if isinstance(entry, dict)
            ]
    if not rules:
        raise RuleConversionError("the DevSkim archive did not contain rules/default")
    return rules


def _normalize_pattern(pattern: dict[str, Any]) -> str:
    if "xpaths" in pattern or "ymlpaths" in pattern:
        raise RuleConversionError("structured path matcher")
    scopes = pattern.get("scopes")
    if isinstance(scopes, list) and "code" not in scopes:
        raise RuleConversionError("not a code scope")

    raw = pattern.get("pattern")
    if not isinstance(raw, str) or not raw:
        raise RuleConversionError("empty pattern")
    pattern_type = str(pattern.get("type") or "regex")
    if pattern_type in {"string", "substring"}:
        text = re.escape(raw)
    elif pattern_type == "RegexWord":
        text = rf"\b(?:{raw})\b"
    elif pattern_type == "regex":
        text = raw
    else:
        raise RuleConversionError(f"unsupported pattern type {pattern_type!r}")

    if any(marker in text for marker in _INCOMPATIBLE_MARKERS):
        raise RuleConversionError("uses a construct Python's re cannot represent")

    # Translate the common .NET regex forms to Python syntax.
    text = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", text)
    text = re.sub(r"\\k<([A-Za-z_]\w*)>", r"(?P=\1)", text)
    text = text.replace(r"\z", r"\Z")

    modifiers = pattern.get("modifiers")
    if isinstance(modifiers, list):
        flags = "".join(
            sorted({str(item)[0] for item in modifiers if str(item)[:1] in _SAFE_MODIFIERS})
        )
        if flags:
            text = f"(?{flags}){text}"
    try:
        re.compile(text)
    except re.error as exc:
        raise RuleConversionError(f"invalid Python regex ({exc})") from exc
    return text


def _glob_from_file_regex(raw: str) -> str:
    text = raw.strip()
    text = text.removeprefix("^")
    text = text.removeprefix(".*")
    text = text.replace(r"\.", ".").replace(".*", "*")
    text = text.rstrip("$")
    if "/" not in text:
        return f"**/{text.lstrip('/')}"
    return text.lstrip("/")


def _languages(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("applies_to")
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for language in raw:
        text = str(language).strip()
        if text and text not in result:
            result.append(text)
    return result


def _paths(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("applies_to_file_regex")
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for entry in raw:
        if isinstance(entry, str) and entry.strip():
            glob = _glob_from_file_regex(entry)
            if glob not in result:
                result.append(glob)
    return result


def _tags(rule: dict[str, Any], group: str) -> list[str]:
    tags = ["general", "devskim", group]
    raw = rule.get("tags")
    if isinstance(raw, list):
        for tag in raw:
            text = str(tag).strip().lower()
            if text and text not in tags:
                tags.append(text)
    return tags


def _description(rule: dict[str, Any]) -> str:
    name = str(rule.get("name") or "DevSkim rule").strip()
    description = str(rule.get("description") or "").strip()
    recommendation = str(rule.get("recommendation") or "").strip()
    text = f"{name}: {description}" if description else name
    if recommendation:
        text = f"{text} Recommendation: {recommendation}"
    return " ".join(text.split())


def _convert_rule(rule: dict[str, Any], group: str) -> dict[str, Any]:
    if rule.get("conditions") or rule.get("expression"):
        raise RuleConversionError("depends on conditional/expression evaluation")
    if rule.get("does_not_apply_to"):
        raise RuleConversionError("depends on language exclusions")

    raw_patterns = rule.get("patterns")
    if not isinstance(raw_patterns, list) or not raw_patterns:
        raise RuleConversionError("no patterns")
    patterns: list[str] = []
    for pattern in raw_patterns:
        if not isinstance(pattern, dict):
            raise RuleConversionError("invalid pattern entry")
        patterns.append(_normalize_pattern(pattern))
    if not patterns:
        raise RuleConversionError("no compatible patterns")

    raw_severity = str(rule.get("severity") or "").lower()
    severity = _SEVERITY.get(raw_severity, "medium")
    confidence = _CONFIDENCE.get(raw_severity, "medium")
    tags = _tags(rule, group)
    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        raise RuleConversionError("missing rule id")

    converted: dict[str, Any] = {
        "id": f"devskim-{rule_id}",
        "description": _description(rule),
        "severity": severity,
        "category": _GROUP_CATEGORY.get(group, "sast"),
        "confidence": confidence,
        "source": "devskim",
        "tags": tags,
        "regex": "(?:{})".format(")|(?:".join(patterns)),
    }
    languages = _languages(rule) or ["code"]
    converted["languages"] = languages
    paths = _paths(rule)
    if paths:
        converted["paths"] = paths
    tag_text = " ".join(tags)
    rule_text = str(rule.get("name") or "").lower()
    if any(marker in tag_text for marker in _SECRET_TAG_MARKERS) or any(
        marker in rule_text for marker in _SECRET_TEXT_MARKERS
    ):
        converted["secret"] = True
        converted["category"] = "secret"
    return converted


def _group_for(path: str) -> str | None:
    for group, prefixes in _GROUPS:
        if any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes):
            return group
    return None


def _write_yaml(path: Path, rules: list[dict[str, Any]], revision: str) -> None:
    header = (
        "# Generated by scripts/fetch_general_rules.py. Do not edit by hand.\n"
        f"# Source: https://github.com/{DEVSKIM_REPOSITORY}\n"
        f"# Revision: {revision}\n"
        "# License: MIT (see rules/general/devskim/LICENSE.txt)\n"
        "# Converted from rules/default; conditional/structured rules are omitted.\n"
    )
    body = yaml.safe_dump(
        {"rules": rules},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
    )
    path.write_text(header + body, encoding="utf-8")


def fetch(
    *,
    revision: str = DEVSKIM_REVISION,
    output: Path = DEFAULT_OUTPUT,
    dry_run: bool = False,
) -> dict[str, Any]:
    source = _download_repository(revision)
    converted: dict[str, list[dict[str, Any]]] = {group: [] for group, _ in _GROUPS}
    skipped: Counter[str] = Counter()
    seen_ids: set[str] = set()

    for relative, entries in sorted(source.items()):
        group = _group_for(relative)
        if group is None:
            skipped["unmapped path"] += len(entries)
            continue
        for entry in entries:
            try:
                rule = _convert_rule(entry, group)
            except RuleConversionError as exc:
                skipped[str(exc)] += 1
                continue
            if rule["id"] in seen_ids:
                skipped["duplicate rule id"] += 1
                continue
            seen_ids.add(rule["id"])
            converted[group].append(rule)

    if not any(converted.values()):
        raise RuleConversionError("no DevSkim rules could be converted")

    if not dry_run:
        output.mkdir(parents=True, exist_ok=True)
        for group, rules in converted.items():
            if rules:
                _write_yaml(output / f"{group}.yaml", rules, revision)
        license_url = (
            f"https://raw.githubusercontent.com/{DEVSKIM_REPOSITORY}/"
            f"{revision}/LICENSE.txt"
        )
        request = urllib.request.Request(
            license_url, headers={"User-Agent": "CommitGuard-rule-updater"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            (output / "LICENSE.txt").write_bytes(response.read())

    total = sum(len(rules) for rules in converted.values())
    return {
        "revision": revision,
        "rules": total,
        "groups": {group: len(rules) for group, rules in converted.items() if rules},
        "skipped": dict(sorted(skipped.items())),
        "output": str(output),
        "dry_run": dry_run,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default=DEVSKIM_REVISION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = fetch(
            revision=args.revision,
            output=args.output.resolve(),
            dry_run=args.dry_run,
        )
    except (OSError, RuleConversionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"DevSkim {result['revision'][:12]}: "
        f"{result['rules']} rules in {len(result['groups'])} groups"
    )
    for group, count in result["groups"].items():
        print(f"  {group:12} {count}")
    if result["skipped"]:
        print("skipped:")
        for reason, count in result["skipped"].items():
            print(f"  {reason}: {count}")
    if result["dry_run"]:
        print("(dry run; no files written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
