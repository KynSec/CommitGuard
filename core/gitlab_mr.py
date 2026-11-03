"""GitLab merge-request summaries and inline suggestions.

The client intentionally uses the small, mockable REST surface that is
available to CI job tokens on gitlab.com and self-managed instances.  No
GitLab Python package is required.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from core.pr_creator import InlineSuggestion, build_inline_suggestions

DEFAULT_API_URL = "https://gitlab.com/api/v4"
SUMMARY_MARKER = "<!-- commitguard-mr-summary -->"
INLINE_MARKER = "<!-- commitguard-inline -->"

Transport = Callable[[str, str, dict[str, Any] | None], Any]


class GitLabAPIError(RuntimeError):
    """Raised when the GitLab API returns an error or cannot be reached."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class GitLabOptions:
    base_url: str = DEFAULT_API_URL
    project_id: str = ""
    token: str = ""
    merge_request_iid: int | None = None
    commit_sha: str | None = None
    diff_base_sha: str | None = None
    start_sha: str | None = None


@dataclass(frozen=True)
class GitLabResult:
    posted: int = 0
    updated: int = 0
    skipped: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


class GitLabClient:
    """Minimal GitLab REST client with an injectable transport for tests."""

    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_API_URL,
        timeout: int = 20,
        transport: Transport | None = None,
    ) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if self._transport is not None:
            return self._transport(method, path, payload)
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Accept": "application/json",
            "PRIVATE-TOKEN": self.token,
            "User-Agent": "CommitGuard/3",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace").strip()
            raise GitLabAPIError(
                f"GitLab API {method} {path} failed: {exc.code} {detail[:300]}",
                status=exc.code,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise GitLabAPIError(f"GitLab request failed: {exc}") from exc
        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise GitLabAPIError("GitLab returned a non-JSON response.") from exc

    def _project_path(self, project_id: str) -> str:
        quoted = urllib.parse.quote(str(project_id), safe="")
        return f"/projects/{quoted}"

    def list_merge_request_notes(self, project_id: str, iid: int) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            f"{self._project_path(project_id)}/merge_requests/{iid}/notes?per_page=100",
        )
        return response if isinstance(response, list) else []

    def create_merge_request_note(
        self, project_id: str, iid: int, body: str
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"{self._project_path(project_id)}/merge_requests/{iid}/notes",
            {"body": body},
        )
        return response if isinstance(response, dict) else {}

    def update_merge_request_note(
        self, project_id: str, iid: int, note_id: int, body: str
    ) -> dict[str, Any]:
        response = self._request(
            "PUT",
            f"{self._project_path(project_id)}/merge_requests/{iid}/notes/{note_id}",
            {"body": body},
        )
        return response if isinstance(response, dict) else {}

    def create_merge_request_discussion(
        self,
        project_id: str,
        iid: int,
        body: str,
        position: dict[str, Any],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"{self._project_path(project_id)}/merge_requests/{iid}/discussions",
            {"body": body, "position": position},
        )
        return response if isinstance(response, dict) else {}

    def list_merge_request_discussions(
        self, project_id: str, iid: int
    ) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            f"{self._project_path(project_id)}/merge_requests/{iid}/discussions"
            "?per_page=100",
        )
        return response if isinstance(response, list) else []

    def latest_diff_refs(self, project_id: str, iid: int) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"{self._project_path(project_id)}/merge_requests/{iid}/versions",
        )
        if isinstance(response, list) and response:
            latest = response[0]
            if isinstance(latest, dict):
                return latest
        return {}


def _positive_int(value: object) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def gitlab_options_from_environment() -> GitLabOptions:
    """Builds options from GitLab CI predefined variables."""
    return GitLabOptions(
        base_url=(
            os.environ.get("CI_API_V4_URL")
            or os.environ.get("GITLAB_API_URL")
            or DEFAULT_API_URL
        ).rstrip("/"),
        project_id=os.environ.get("CI_PROJECT_ID", "").strip(),
        token=(
            os.environ.get("GITLAB_TOKEN")
            or os.environ.get("CI_JOB_TOKEN")
            or ""
        ).strip(),
        merge_request_iid=_positive_int(os.environ.get("CI_MERGE_REQUEST_IID")),
        commit_sha=os.environ.get("CI_COMMIT_SHA", "").strip() or None,
        diff_base_sha=(
            os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA", "").strip() or None
        ),
        start_sha=(
            os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_SHA", "").strip() or None
        ),
    )


def _severity_counts(findings: list) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(getattr(finding, "severity", "info")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def build_gitlab_summary(
    findings: list,
    *,
    block_threshold: str = "high",
    dependency_graph: str | None = None,
    max_findings: int = 25,
) -> str:
    """Builds an MR summary without ever including flagged code."""
    counts = _severity_counts(findings)
    blocking = sum(
        count
        for severity, count in counts.items()
        if _severity_rank(severity) >= _severity_rank(block_threshold)
    )
    lines = [
        SUMMARY_MARKER,
        "## CommitGuard security report",
        "",
        f"**Blocking:** {blocking} at or above `{block_threshold}`  ",
        "**Severity:** "
        + ", ".join(f"{name} {count}" for name, count in counts.items() if count),
        "",
    ]
    if not findings:
        lines.append("No security findings in this merge request.")
    else:
        lines.extend(
            [
                "| Severity | Rule | File | Line |",
                "| --- | --- | --- | --- |",
            ]
        )
        for finding in findings[:max_findings]:
            lines.append(
                f"| {getattr(finding, 'severity', 'info')} "
                f"| `{getattr(finding, 'rule_id', '')}` "
                f"| `{getattr(finding, 'file', '')}` "
                f"| {getattr(finding, 'line_number', '')} |"
            )
        if len(findings) > max_findings:
            lines.append("")
            lines.append(f"_{len(findings) - max_findings} more finding(s) omitted._")
    if dependency_graph:
        lines.extend(["", dependency_graph])
    lines.extend(
        [
            "",
            "Generated by CommitGuard — offline-first, no telemetry.",
        ]
    )
    return "\n".join(lines) + "\n"


def _severity_rank(value: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(value.lower(), 0)


def publish_gitlab_summary(
    client: GitLabClient,
    options: GitLabOptions,
    body: str,
) -> GitLabResult:
    """Creates or updates the single marker-based MR summary note."""
    if options.merge_request_iid is None:
        raise GitLabAPIError("Could not determine CI_MERGE_REQUEST_IID.")
    if not options.project_id:
        raise GitLabAPIError("Could not determine CI_PROJECT_ID.")
    existing = None
    for note in client.list_merge_request_notes(
        options.project_id, options.merge_request_iid
    ):
        if SUMMARY_MARKER in str(note.get("body", "")):
            existing = note
            break
    if existing is not None:
        client.update_merge_request_note(
            options.project_id,
            options.merge_request_iid,
            int(existing.get("id", 0)),
            body,
        )
        return GitLabResult(updated=1)
    client.create_merge_request_note(
        options.project_id, options.merge_request_iid, body
    )
    return GitLabResult(posted=1)


def build_gitlab_inline_suggestions(
    findings: list,
    rules: tuple | list,
    *,
    max_suggestions: int = 50,
) -> list[InlineSuggestion]:
    """Reuses the GitHub suggestion builder so both platforms stay identical."""
    return build_inline_suggestions(
        findings, rules, max_suggestions=max_suggestions
    )


def publish_gitlab_inline_suggestions(
    client: GitLabClient,
    options: GitLabOptions,
    suggestions: list[InlineSuggestion],
) -> GitLabResult:
    """Posts click-to-apply suggestions as GitLab MR discussions."""
    if options.merge_request_iid is None:
        raise GitLabAPIError("Could not determine CI_MERGE_REQUEST_IID.")
    if not options.project_id:
        raise GitLabAPIError("Could not determine CI_PROJECT_ID.")
    if not suggestions:
        return GitLabResult(skipped=0)
    refs = {
        "base_sha": options.diff_base_sha,
        "start_sha": options.start_sha,
        "head_sha": options.commit_sha,
    }
    if not all(refs.values()):
        latest = client.latest_diff_refs(options.project_id, options.merge_request_iid)
        for key, value in refs.items():
            if not value:
                refs[key] = str(latest.get(key, "") or "")
    missing = [key for key, value in refs.items() if not value]
    if missing:
        raise GitLabAPIError(
            "Could not resolve merge request diff refs: " + ", ".join(missing)
        )
    existing: set[tuple[str, int]] = set()
    for discussion in client.list_merge_request_discussions(
        options.project_id, options.merge_request_iid
    ):
        for note in discussion.get("notes", []):
            if INLINE_MARKER not in str(note.get("body", "")):
                continue
            position = note.get("position") or {}
            path = str(position.get("new_path", ""))
            line = _positive_int(position.get("new_line"))
            if path and line is not None:
                existing.add((path, line))
    posted = 0
    skipped = 0
    warnings: list[str] = []
    for suggestion in suggestions:
        if (suggestion.path, suggestion.line) in existing:
            skipped += 1
            continue
        position = {
            "position_type": "text",
            "base_sha": refs["base_sha"],
            "start_sha": refs["start_sha"],
            "head_sha": refs["head_sha"],
            "new_path": suggestion.path,
            "new_line": suggestion.line,
        }
        try:
            client.create_merge_request_discussion(
                options.project_id,
                options.merge_request_iid,
                suggestion.body,
                position,
            )
        except GitLabAPIError as exc:
            warnings.append(f"{suggestion.path}:{suggestion.line}: {exc}")
            continue
        posted += 1
    return GitLabResult(posted=posted, skipped=skipped, warnings=tuple(warnings))
