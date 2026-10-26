"""SARIF 2.1.0 and native tool adapters.

Ingest is deliberately offline and read-only: URIs and commands embedded in a
report are never executed.  Unknown fields are preserved in ``provenance``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from core.findings import (
    canonical_path,
    extract_findings,
    fingerprint,
    infer_category,
    infer_confidence,
)
from core.scanner import Finding

MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_RESULTS = 100_000
_TOOLS = ("semgrep", "codeql", "trivy", "checkov", "gitleaks", "bandit")

_LEVEL_SEVERITY = {
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "note": "low",
    "low": "low",
    "info": "info",
    "none": "info",
    "informational": "info",
    "unknown": "medium",
}
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)"
    r"(\s*[:=]\s*)(['\"]?)([A-Za-z0-9_+\-/=]{8,})(['\"]?)"
)


class IngestError(ValueError):
    """Raised when a report is malformed, oversized, or unsupported."""


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"


def _severity(value: Any, default: str = "medium") -> str:
    if value is None:
        return default
    text = str(value).strip().lower()
    return _LEVEL_SEVERITY.get(text, default)


def _mask(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        secret = match.group(4)
        if len(secret) <= 4:
            masked = "****"
        elif len(secret) <= 8:
            masked = secret[0] + "****" + secret[-1]
        else:
            masked = secret[:2] + "********" + secret[-2:]
        return f"{match.group(1)}{match.group(2)}{match.group(3)}{masked}{match.group(5)}"

    return _SECRET_ASSIGNMENT_RE.sub(replace, value)


def _cwe(value: Any) -> str | None:
    values: list[str] = []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, Mapping):
        raw_id = value.get("id")
        if raw_id is not None:
            values = [f"CWE-{raw_id}"]
    elif isinstance(value, (list, tuple)):
        values = [str(item) for item in value]
    for item in values:
        match = _CWE_RE.search(item)
        if match:
            return match.group(0).upper().replace("CWE", "CWE")
    return None


def _safe_path(raw: Any, repo_root: str | Path | None) -> str:
    try:
        return canonical_path(str(raw), repo_root)
    except ValueError as exc:
        raise IngestError(str(exc)) from exc


def _make_finding(
    *,
    tool: str,
    rule_id: str,
    file: str,
    line: int,
    description: str,
    severity: str,
    repo_root: str | Path | None,
    column: int | None = None,
    end_line: int | None = None,
    end_column: int | None = None,
    category: str = "",
    tags: Iterable[str] = (),
    cwe: str | None = None,
    code: str = "",
    fix: dict[str, Any] | None = None,
    references: Iterable[str] = (),
    flows: Iterable[dict[str, Any]] = (),
    baseline_state: str = "new",
    blocked: bool = True,
    original_severity: str = "",
    tool_version: str = "",
    extra_provenance: Mapping[str, Any] | None = None,
) -> Finding:
    path = _safe_path(file, repo_root)
    line = max(line, 1)
    tags_tuple = tuple(sorted({str(tag) for tag in tags if str(tag)}))
    category = category or infer_category(
        rule_id=rule_id,
        source=f"ingest:{tool}",
        tags=tags_tuple,
        cwe=cwe,
    )
    if category == "secret":
        code = _mask(code)
        description = _mask(description)
    engine = f"ingest:{_slug(tool)}"
    provenance = {
        "input_format": "native",
        "tool": tool,
        "tool_version": tool_version,
        "original_rule_id": rule_id,
        "original_severity": original_severity or severity,
    }
    if extra_provenance:
        provenance.update(dict(extra_provenance))
    return Finding(
        file=path,
        line_number=max(1, int(line)),
        rule_id=rule_id,
        description=description or rule_id,
        severity=severity,
        source=f"ingest:{tool}",
        flagged_code=code,
        redacted_code=code,
        fingerprint=fingerprint(rule_id, path, code or description),
        tags=tags_tuple,
        cwe=cwe,
        blocking=blocked,
        baseline_state=baseline_state,
        id="",
        engine=engine,
        category=category,
        confidence=infer_confidence(engine),
        column=column or None,
        end_line=end_line or None,
        end_column=end_column or None,
        fix=fix,
        references=tuple(str(item) for item in references if item),
        code_flows=tuple(dict(flow) for flow in flows),
        rule_version=str(provenance.get("rule_version") or ""),
        pack_version="",
        provenance=provenance,
    )


def _sarif_region(location: Mapping[str, Any]) -> tuple[str, int, int | None, int | None, int | None, str]:
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    path = str(artifact.get("uri") or artifact.get("index") or "")
    line = int(region.get("startLine") or 1)
    column = int(region.get("startColumn") or 0) or None
    end_line = int(region.get("endLine") or 0) or None
    end_column = int(region.get("endColumn") or 0) or None
    snippet = ""
    raw_snippet = region.get("snippet") or {}
    if isinstance(raw_snippet, Mapping):
        snippet = str(raw_snippet.get("text") or "")
    return path, line, column, end_line, end_column, snippet


def _sarif_fix(fixes: Any, file: str) -> dict[str, Any] | None:
    if not isinstance(fixes, list) or not fixes:
        return None
    first = fixes[0]
    if not isinstance(first, Mapping):
        return None
    description = ""
    raw_description = first.get("description")
    if isinstance(raw_description, Mapping):
        description = str(raw_description.get("text") or "")
    edits: list[dict[str, Any]] = []
    for change in first.get("artifactChanges", []) if isinstance(first.get("artifactChanges"), list) else []:
        if not isinstance(change, Mapping):
            continue
        for replacement in change.get("replacements", []) if isinstance(change.get("replacements"), list) else []:
            if not isinstance(replacement, Mapping):
                continue
            region = replacement.get("deletedRegion") or {}
            inserted = replacement.get("insertedContent") or {}
            edits.append(
                {
                    "start_line": int(region.get("startLine") or 1),
                    "end_line": int(region.get("endLine") or region.get("startLine") or 1),
                    "start_column": region.get("startColumn"),
                    "end_column": region.get("endColumn"),
                    "replacement": str(inserted.get("text") or ""),
                }
            )
    if not edits:
        return None
    return {
        "description": description or "Apply the tool's suggested fix",
        "safety": "review",
        "edits": edits,
    }


def _sarif_flows(code_flows: Any, fallback_file: str) -> list[dict[str, Any]]:
    if not isinstance(code_flows, list) or not code_flows:
        return []
    flows: list[dict[str, Any]] = []
    first = code_flows[0]
    if not isinstance(first, Mapping):
        return []
    thread_flows = first.get("threadFlows") or []
    if not isinstance(thread_flows, list) or not thread_flows:
        return []
    thread = thread_flows[0] if isinstance(thread_flows[0], Mapping) else {}
    for item in thread.get("locations", []) if isinstance(thread.get("locations"), list) else []:
        if not isinstance(item, Mapping):
            continue
        location = item.get("location") or {}
        path, line, _column, _end_line, _end_column, _snippet = _sarif_region(location)
        message = ""
        raw_message = location.get("message")
        if isinstance(raw_message, Mapping):
            message = str(raw_message.get("text") or "")
        flows.append(
            {
                "file": path or fallback_file,
                "line": line,
                "message": message or "data flow",
            }
        )
    return flows


def ingest_sarif(
    document: Mapping[str, Any], *, repo_root: str | Path | None = None
) -> list[Finding]:
    if not isinstance(document, Mapping):
        raise IngestError("SARIF document must be an object")
    version = str(document.get("version") or "")
    if not version.startswith("2."):
        raise IngestError(f"unsupported SARIF version: {version or 'missing'}")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise IngestError("SARIF document is missing runs[]")
    findings: list[Finding] = []
    total = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise IngestError(f"SARIF run {run_index} must be an object")
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = str(driver.get("name") or "unknown")
        tool_version = str(driver.get("version") or "")
        rules_raw = driver.get("rules") or []
        rules: dict[str, Mapping[str, Any]] = {}
        if isinstance(rules_raw, list):
            for rule in rules_raw:
                if isinstance(rule, Mapping) and rule.get("id"):
                    rules[str(rule["id"])] = rule
        results = run.get("results") or []
        if not isinstance(results, list):
            raise IngestError(f"SARIF run {run_index}.results must be a list")
        for result in results:
            total += 1
            if total > MAX_RESULTS:
                raise IngestError("SARIF report contains too many results")
            if not isinstance(result, Mapping):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id, {})
            if not rule_id and result.get("ruleIndex") is not None:
                try:
                    indexed = rules_raw[int(result["ruleIndex"])]
                    rule_id = (
                        str(indexed.get("id", ""))
                        if isinstance(indexed, Mapping)
                        else ""
                    )
                except (TypeError, ValueError, IndexError):
                    rule_id = ""
            rule_id = rule_id or "sarif/unknown"
            locations = result.get("locations") or []
            if not isinstance(locations, list) or not locations:
                continue
            path, line, column, end_line, end_column, snippet = _sarif_region(
                locations[0] if isinstance(locations[0], Mapping) else {}
            )
            properties = _as_mapping(rule.get("properties"))
            result_props = _as_mapping(result.get("properties"))
            tags = result_props.get("tags") or properties.get("tags") or []
            tags_tuple = tuple(str(tag) for tag in tags) if isinstance(tags, list) else ()
            cwe = _cwe(result_props.get("cwe") or properties.get("cwe") or [])
            if cwe is None:
                cwe = _cwe(tags_tuple)
            severity_value = (
                result_props.get("severity")
                or properties.get("severity")
                or result.get("level")
                or ((rule.get("defaultConfiguration") or {}).get("level"))
            )
            severity = _severity(severity_value)
            message = ""
            raw_message = result.get("message")
            if isinstance(raw_message, Mapping):
                message = str(raw_message.get("text") or "")
            elif isinstance(raw_message, str):
                message = raw_message
            if not message:
                short = rule.get("shortDescription") or {}
                message = str(short.get("text") or rule_id) if isinstance(short, Mapping) else rule_id
            category = infer_category(
                rule_id=rule_id,
                source=f"ingest:{tool_name}",
                tags=tags_tuple,
                cwe=cwe,
            )
            suppressions = result.get("suppressions")
            blocked = not bool(suppressions)
            baseline_state = str(result.get("baselineState") or "new")
            partials = result.get("partialFingerprints") or {}
            fp = ""
            if isinstance(partials, Mapping):
                fp = str(
                    partials.get("primaryLocationLineHash")
                    or partials.get("commitGuard/v1")
                    or ""
                )
            fix = _sarif_fix(result.get("fixes"), path)
            flows = _sarif_flows(result.get("codeFlows"), path)
            extra: dict[str, Any] = {"run_index": run_index}
            if partials:
                extra["partial_fingerprints"] = dict(partials)
            if suppressions:
                extra["suppressions"] = suppressions
            finding = _make_finding(
                tool=tool_name,
                rule_id=rule_id,
                file=path or "unknown",
                line=line,
                description=message,
                severity=severity,
                repo_root=repo_root,
                column=column,
                end_line=end_line,
                end_column=end_column,
                category=category,
                tags=tags_tuple,
                cwe=cwe,
                code=snippet,
                fix=fix,
                references=(
                    [str(rule.get("helpUri"))] if rule.get("helpUri") else []
                ),
                flows=flows,
                baseline_state=baseline_state,
                blocked=blocked,
                original_severity=str(severity_value or ""),
                tool_version=tool_version,
                extra_provenance=extra,
            )
            if fp:
                finding = Finding(
                    **{
                        **finding.__dict__,
                        "fingerprint": fp,
                        "id": fp,
                    }
                )
            findings.append(finding)
    return findings


def ingest_semgrep(
    document: Any, *, repo_root: str | Path | None = None, tool: str = "semgrep"
) -> list[Finding]:
    if isinstance(document, Mapping) and "results" in document:
        results = document.get("results")
    elif isinstance(document, list):
        results = document
    else:
        raise IngestError("Semgrep report must contain results[]")
    if not isinstance(results, list):
        raise IngestError("Semgrep results must be a list")
    findings = []
    for result in results:
        if not isinstance(result, Mapping):
            continue
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}
        cwe = _cwe(metadata.get("cwe"))
        tags = tuple(str(tag) for tag in metadata.get("tags", []) if tag)
        rule_id = str(result.get("check_id") or "semgrep/unknown")
        category = infer_category(
            rule_id=rule_id,
            source=f"ingest:{tool}",
            tags=tags,
            cwe=cwe,
        )
        message = str(extra.get("message") or rule_id)
        fix = None
        raw_fix = extra.get("fix")
        if isinstance(raw_fix, str):
            fix = {
                "description": "Apply Semgrep autofix",
                "safety": "review",
                "edits": [
                    {
                        "start_line": int(start.get("line") or 1),
                        "end_line": int(end.get("line") or start.get("line") or 1),
                        "start_column": start.get("col"),
                        "end_column": end.get("col"),
                        "replacement": raw_fix,
                    }
                ],
            }
        findings.append(
            _make_finding(
                tool=tool,
                rule_id=rule_id,
                file=str(result.get("path") or "unknown"),
                line=int(start.get("line") or 1),
                description=message,
                severity=_severity(extra.get("severity")),
                repo_root=repo_root,
                column=int(start.get("col") or 0) or None,
                end_line=int(end.get("line") or 0) or None,
                end_column=int(end.get("col") or 0) or None,
                category=category,
                tags=tags,
                cwe=cwe,
                code=str(extra.get("lines") or ""),
                fix=fix,
                references=metadata.get("references", []),
                original_severity=str(extra.get("severity") or ""),
                extra_provenance={"fingerprint": result.get("fingerprint", "")},
            )
        )
    return findings


def ingest_gitleaks(
    document: Any, *, repo_root: str | Path | None = None
) -> list[Finding]:
    items = document if isinstance(document, list) else []
    if not isinstance(items, list):
        raise IngestError("gitleaks report must be a list")
    findings = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        rule_id = str(item.get("RuleID") or "gitleaks/unknown")
        tags = tuple(str(tag) for tag in item.get("Tags", []) or ())
        path = str(item.get("File") or "unknown")
        findings.append(
            _make_finding(
                tool="gitleaks",
                rule_id=f"gitleaks/{rule_id}",
                file=path,
                line=int(item.get("StartLine") or 1),
                description=str(
                    item.get("Description")
                    or f"Potential secret detected by {rule_id}"
                ),
                severity="high",
                repo_root=repo_root,
                column=int(item.get("StartColumn") or 0) or None,
                end_line=int(item.get("EndLine") or 0) or None,
                end_column=int(item.get("EndColumn") or 0) or None,
                category="secret",
                tags=("secret", *tags),
                cwe="CWE-798",
                code=str(item.get("Match") or ""),
                original_severity="high",
                extra_provenance={
                    "fingerprint": item.get("Fingerprint", ""),
                    "commit": item.get("Commit", ""),
                    "author": item.get("Author", ""),
                    "entropy": item.get("Entropy"),
                },
            )
        )
    return findings


def ingest_trivy(
    document: Any, *, repo_root: str | Path | None = None
) -> list[Finding]:
    if not isinstance(document, Mapping):
        raise IngestError("Trivy report must be an object")
    findings: list[Finding] = []
    results = document.get("Results") or []
    if not isinstance(results, list):
        raise IngestError("Trivy Results must be a list")
    for result in results:
        if not isinstance(result, Mapping):
            continue
        target = str(result.get("Target") or "unknown")
        result_class = str(result.get("Class") or result.get("Type") or "").lower()
        for vulnerability in result.get("Vulnerabilities", []) or []:
            if not isinstance(vulnerability, Mapping):
                continue
            vuln_id = str(vulnerability.get("VulnerabilityID") or "trivy/unknown")
            package = str(vulnerability.get("PkgName") or "")
            fixed = vulnerability.get("FixedVersion")
            findings.append(
                _make_finding(
                    tool="trivy",
                    rule_id=f"trivy/{vuln_id}",
                    file=target,
                    line=1,
                    description=str(
                        vulnerability.get("Title")
                        or f"{package} is affected by {vuln_id}"
                    ),
                    severity=_severity(vulnerability.get("Severity")),
                    repo_root=repo_root,
                    category="dependency",
                    tags=("dependency", "sca"),
                    cwe=_cwe(vulnerability.get("CweIDs")),
                    code=f"{package}=={vulnerability.get('InstalledVersion', '')}",
                    references=(
                        [str(vulnerability.get("PrimaryURL"))]
                        if vulnerability.get("PrimaryURL")
                        else []
                    ),
                    original_severity=str(vulnerability.get("Severity") or ""),
                    extra_provenance={
                        "package": package,
                        "installed_version": vulnerability.get("InstalledVersion", ""),
                        "fixed_version": fixed,
                    },
                )
            )
        for misconfiguration in result.get("Misconfigurations", []) or []:
            if not isinstance(misconfiguration, Mapping):
                continue
            check_id = str(
                misconfiguration.get("ID")
                or misconfiguration.get("AVDID")
                or "trivy/unknown"
            )
            findings.append(
                _make_finding(
                    tool="trivy",
                    rule_id=f"trivy/{check_id}",
                    file=str(
                        misconfiguration.get("CauseMetadata", {}).get("Resource")
                        or target
                    ),
                    line=int(
                        (misconfiguration.get("CauseMetadata") or {}).get("StartLine")
                        or 1
                    ),
                    description=str(
                        misconfiguration.get("Title")
                        or misconfiguration.get("Message")
                        or check_id
                    ),
                    severity=_severity(misconfiguration.get("Severity")),
                    repo_root=repo_root,
                    category="iac" if result_class != "container" else "container",
                    tags=("iac", result_class or "config"),
                    references=(
                        [str(misconfiguration.get("PrimaryURL"))]
                        if misconfiguration.get("PrimaryURL")
                        else []
                    ),
                    original_severity=str(misconfiguration.get("Severity") or ""),
                )
            )
    return findings


def ingest_checkov(
    document: Any, *, repo_root: str | Path | None = None
) -> list[Finding]:
    if not isinstance(document, Mapping):
        raise IngestError("Checkov report must be an object")
    results = document.get("results") or {}
    checks = results.get("failed_checks") if isinstance(results, Mapping) else None
    if checks is None and isinstance(document.get("failed_checks"), list):
        checks = document["failed_checks"]
    if not isinstance(checks, list):
        raise IngestError("Checkov report is missing failed_checks[]")
    findings = []
    for check in checks:
        if not isinstance(check, Mapping):
            continue
        check_id = str(check.get("check_id") or check.get("bc_check_id") or "checkov/unknown")
        line_range = check.get("file_line_range") or [1, 1]
        line = int(line_range[0] or 1) if isinstance(line_range, list) else 1
        end_line = int(line_range[1] or line) if isinstance(line_range, list) else line
        findings.append(
            _make_finding(
                tool="checkov",
                rule_id=f"checkov/{check_id}",
                file=str(check.get("file_path") or check.get("repo_file_path") or "unknown"),
                line=line,
                description=str(check.get("check_name") or check_id),
                severity=_severity(check.get("severity"), "medium"),
                repo_root=repo_root,
                end_line=end_line,
                category="iac",
                tags=("iac", "terraform"),
                code=str(check.get("resource") or ""),
                references=(
                    [str(check.get("guideline"))] if check.get("guideline") else []
                ),
                original_severity=str(check.get("severity") or ""),
            )
        )
    return findings


def ingest_bandit(
    document: Any, *, repo_root: str | Path | None = None
) -> list[Finding]:
    if not isinstance(document, Mapping):
        raise IngestError("Bandit report must be an object")
    results = document.get("results") or []
    if not isinstance(results, list):
        raise IngestError("Bandit results must be a list")
    findings = []
    for result in results:
        if not isinstance(result, Mapping):
            continue
        test_id = str(result.get("test_id") or "bandit/unknown")
        findings.append(
            _make_finding(
                tool="bandit",
                rule_id=f"bandit/{test_id}",
                file=str(result.get("filename") or "unknown"),
                line=int(result.get("line_number") or 1),
                description=str(result.get("issue_text") or result.get("test_name") or test_id),
                severity=_severity(result.get("issue_severity"), "medium"),
                repo_root=repo_root,
                column=int(result.get("col_offset") or 0) + 1 or None,
                end_column=int(result.get("end_col_offset") or 0) or None,
                category="sast",
                tags=("sast", "python"),
                cwe=_cwe(result.get("issue_cwe")),
                code=str(result.get("code") or ""),
                references=(
                    [str(result.get("more_info"))] if result.get("more_info") else []
                ),
                original_severity=str(result.get("issue_severity") or ""),
            )
        )
    return findings


def _detect_tool(document: Any) -> str:
    if isinstance(document, Mapping):
        if "runs" in document and "version" in document:
            return "sarif"
        if "findings" in document:
            return "commitguard"
        if "Results" in document:
            return "trivy"
        if "results" in document:
            results = document["results"]
            if isinstance(results, Mapping) and "failed_checks" in results:
                return "checkov"
            if isinstance(results, list):
                first = results[0] if results else {}
                if isinstance(first, Mapping):
                    if "check_id" in first and "path" in first:
                        return "semgrep"
                    if "test_id" in first:
                        return "bandit"
        if "failed_checks" in document:
            return "checkov"
    if isinstance(document, list):
        if not document:
            return "unknown"
        first = document[0]
        if isinstance(first, Mapping):
            if "RuleID" in first or "RuleId" in first:
                return "gitleaks"
            if "check_id" in first and "path" in first:
                return "semgrep"
    return "unknown"


def ingest_data(
    document: Any,
    *,
    tool: str = "auto",
    repo_root: str | Path | None = None,
) -> list[Finding]:
    selected = tool.lower()
    if selected == "auto":
        selected = _detect_tool(document)
    if selected == "sarif":
        if not isinstance(document, Mapping):
            raise IngestError("SARIF document must be an object")
        return ingest_sarif(document, repo_root=repo_root)
    if selected == "semgrep":
        return ingest_semgrep(document, repo_root=repo_root)
    if selected == "gitleaks":
        return ingest_gitleaks(document, repo_root=repo_root)
    if selected == "trivy":
        return ingest_trivy(document, repo_root=repo_root)
    if selected == "checkov":
        return ingest_checkov(document, repo_root=repo_root)
    if selected == "bandit":
        return ingest_bandit(document, repo_root=repo_root)
    if selected == "codeql":
        if not isinstance(document, Mapping):
            raise IngestError("CodeQL must be supplied as SARIF")
        return ingest_sarif(document, repo_root=repo_root)
    if selected == "commitguard":
        return extract_findings(document)
    raise IngestError(
        f"unknown or undetected tool: {tool!r}; expected one of "
        f"{', '.join(_TOOLS)} or auto"
    )


def load_json(path: str | Path) -> Any:
    report_path = Path(path).expanduser()
    try:
        size = report_path.stat().st_size
    except OSError as exc:
        raise IngestError(f"could not read report {report_path}: {exc}") from exc
    if size > MAX_REPORT_BYTES:
        raise IngestError(
            f"report {report_path} is too large ({size} bytes; max {MAX_REPORT_BYTES})"
        )
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestError(f"could not read report {report_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid JSON in {report_path}: {exc}") from exc


def ingest_file(
    path: str | Path,
    *,
    tool: str = "auto",
    repo_root: str | Path | None = None,
) -> list[Finding]:
    document = load_json(path)
    findings = ingest_data(document, tool=tool, repo_root=repo_root)
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "utf-8", "replace"
        )
    ).hexdigest()[:16]
    return [
        Finding(
            **{
                **finding.__dict__,
                "provenance": {
                    **(finding.provenance or {}),
                    "input_digest": digest,
                    "input_path": str(path),
                },
            }
        )
        for finding in findings
    ]


def ingest_files(
    paths: Iterable[str | Path],
    *,
    tool: str = "auto",
    repo_root: str | Path | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(ingest_file(path, tool=tool, repo_root=repo_root))
    return findings
