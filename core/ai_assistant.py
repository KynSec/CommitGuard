"""Local-first AI assistant helpers.

The default provider is deterministic and fully offline: it turns findings into
short, actionable explanations and a token-bounded context package that a
developer can paste into any LLM.  Secret values are always redacted, and no
network request is made unless a caller explicitly opts into a remote provider.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from core.scanner import Finding

DEFAULT_MAX_CHARS = 12000
DEFAULT_PROVIDER = "local"


def _is_allowed_ai_base_url(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
    except ValueError:
        return False

    hostname = parsed.hostname
    scheme = parsed.scheme.lower()
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or scheme not in {"https", "http"}
    ):
        return False
    if scheme == "https":
        return True
    if hostname.lower() == "localhost":  # commit-guard-ignore: devskim-DS162092
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


_REMEDIATION_BY_CATEGORY = {
    "secret": (
        "Rotate the exposed credential immediately, remove it from the working "
        "tree, and purge it from history before the next release."
    ),
    "dependency": (
        "Upgrade the affected package to a patched version, or apply the "
        "vendor workaround and record a VEX decision."
    ),
    "sast": (
        "Validate and encode untrusted input, and replace the flagged sink with "
        "a safe API for the framework in use."
    ),
    "injection": (
        "Use parameterized queries or safe templating; never concatenate "
        "untrusted input into commands, SQL, or markup."
    ),
    "iac": (
        "Harden the resource configuration and pin the provider version so the "
        "fix cannot silently regress."
    ),
    "container": (
        "Use a minimal, pinned base image and remove the unnecessary capability "
        "or package that triggered the finding."
    ),
    "license": (
        "Replace the dependency or obtain legal approval, then record the "
        "decision in the license policy."
    ),
    "quality": "Address the defect before merging; it can mask a security issue.",
}


class AIError(RuntimeError):
    """Raised when an AI context or provider request cannot be built."""


@dataclass(frozen=True)
class AIContext:
    """A redacted, self-contained description of one finding."""

    finding_id: str
    rule_id: str
    severity: str
    category: str
    cwe: str | None
    file: str
    line: int
    description: str
    code: str
    remediation: str
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "code": self.code,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "references": list(self.references),
        }

    def to_markdown(self) -> str:
        lines = [
            f"### {self.rule_id} ({self.severity})",
            f"- Location: `{self.file}:{self.line}`",
            f"- Category: {self.category}",
        ]
        if self.cwe:
            lines.append(f"- Weakness: {self.cwe}")
        lines.append(f"- What: {self.description}")
        if self.code:
            lines.append("- Evidence:")
            lines.append("```")
            lines.append(self.code)
            lines.append("```")
        lines.append(f"- Remediation: {self.remediation}")
        if self.references:
            lines.append("- References: " + ", ".join(self.references))
        return "\n".join(lines)


@dataclass(frozen=True)
class ContextPackage:
    """A deterministic, token-bounded bundle for an external model."""

    repository: str
    generated_at: str
    provider: str
    findings: tuple[AIContext, ...] = ()
    truncated: bool = False
    max_chars: int = DEFAULT_MAX_CHARS

    @property
    def approximate_tokens(self) -> int:
        return math.ceil(len(self.to_markdown()) / 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "generated_at": self.generated_at,
            "provider": self.provider,
            "max_chars": self.max_chars,
            "truncated": self.truncated,
            "approximate_tokens": self.approximate_tokens,
            "findings": [item.to_dict() for item in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            "# CommitGuard AI context",
            "",
            f"Repository: `{self.repository}`",
            f"Generated: {self.generated_at}",
            f"Provider: {self.provider}",
            "",
            "This bundle is redacted. Secret values never appear in the context.",
            "",
        ]
        for item in self.findings:
            lines.append(item.to_markdown())
            lines.append("")
        if self.truncated:
            lines.append("_Context truncated to fit the configured size budget._")
        return "\n".join(lines).rstrip() + "\n"


def remediation_for(finding: Finding) -> str:
    """Returns deterministic remediation guidance for a finding."""
    if finding.fixed_versions:
        return (
            "Upgrade to a patched release: "
            + ", ".join(finding.fixed_versions)
            + ". Verify the application still builds and tests pass."
        )
    fix = getattr(finding, "fix", None)
    if isinstance(fix, dict) and fix.get("replacement"):
        return f"Replace the flagged code with: {fix['replacement']}"
    category = (finding.category or "").lower()
    if category in _REMEDIATION_BY_CATEGORY:
        return _REMEDIATION_BY_CATEGORY[category]
    for tag in finding.tags:
        text = tag.lower()
        if text in _REMEDIATION_BY_CATEGORY:
            return _REMEDIATION_BY_CATEGORY[text]
    return (
        "Follow the rule guidance, add a regression test, and record any "
        "accepted risk in triage with an owner and expiry."
    )


def context_from_finding(finding: Finding) -> AIContext:
    return AIContext(
        finding_id=finding.id or finding.fingerprint,
        rule_id=finding.rule_id,
        severity=finding.severity,
        category=finding.category,
        cwe=finding.cwe,
        file=finding.file,
        line=finding.line_number,
        description=finding.description,
        code=finding.display_code(show_secrets=False),
        remediation=remediation_for(finding),
        tags=tuple(finding.tags),
        references=tuple(getattr(finding, "references", ()) or ()),
    )


def build_context_package(
    repository: str | Path,
    findings: Iterable[Finding],
    *,
    provider: str = DEFAULT_PROVIDER,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> ContextPackage:
    """Builds a redacted, size-bounded context package from findings."""
    if max_chars < 200:
        raise AIError("max_chars must be at least 200")
    selected: list[AIContext] = []
    used = 0
    truncated = False
    for finding in findings:
        item = context_from_finding(finding)
        size = len(item.to_markdown())
        if selected and used + size > max_chars:
            truncated = True
            break
        if not selected and size > max_chars:
            truncated = True
            selected.append(item)
            break
        selected.append(item)
        used += size
    return ContextPackage(
        repository=str(repository),
        generated_at=datetime.now(UTC).isoformat(),
        provider=provider,
        findings=tuple(selected),
        truncated=truncated,
        max_chars=max_chars,
    )


def explain_finding(finding: Finding) -> str:
    """Returns a deterministic, offline explanation for one finding."""
    return context_from_finding(finding).to_markdown()


def format_explanation(
    findings: Iterable[Finding],
    *,
    fmt: str = "text",
) -> str:
    items = [context_from_finding(finding) for finding in findings]
    if fmt == "json":
        return json.dumps(
            {"findings": [item.to_dict() for item in items]}, indent=2
        ) + "\n"
    if fmt == "markdown":
        return "\n\n".join(item.to_markdown() for item in items) + "\n"
    return "\n\n".join(item.to_markdown() for item in items) + "\n"


class Provider(Protocol):
    """An explanation provider."""

    name: str

    def explain(self, context: AIContext) -> str: ...


class LocalTemplateProvider:
    """Deterministic offline provider; the default and safest option."""

    name = DEFAULT_PROVIDER

    def explain(self, context: AIContext) -> str:
        return context.to_markdown()


class OpenAICompatibleProvider:
    """Opt-in remote provider for any OpenAI-compatible chat endpoint.

    The provider is never selected implicitly.  Callers must pass
    ``allow_network=True`` and configure ``COMMITGUARD_AI_BASE_URL``,
    ``COMMITGUARD_AI_API_KEY``, and ``COMMITGUARD_AI_MODEL``.
    """

    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("COMMITGUARD_AI_BASE_URL", "")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("COMMITGUARD_AI_API_KEY", "")
        self.model = model or os.environ.get("COMMITGUARD_AI_MODEL", "")
        self.timeout = timeout

    def explain(self, context: AIContext) -> str:
        if not self.base_url or not self.api_key or not self.model:
            raise AIError(
                "remote provider needs COMMITGUARD_AI_BASE_URL, "
                "COMMITGUARD_AI_API_KEY, and COMMITGUARD_AI_MODEL"
            )
        if not _is_allowed_ai_base_url(self.base_url):
            raise AIError("remote provider base URL must use HTTPS or loopback HTTP")
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security reviewer. Explain the finding and give "
                        "a concrete, minimal remediation. Do not request secrets."
                    ),
                },
                {"role": "user", "content": context.to_markdown()},
            ],
            "temperature": 0.1,
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                document = json.loads(response.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AIError(f"remote provider request failed: {exc}") from exc
        try:
            return str(document["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise AIError("remote provider returned an unexpected response") from exc


def resolve_provider(
    name: str = DEFAULT_PROVIDER,
    *,
    allow_network: bool = False,
) -> Provider:
    """Returns a provider by name, refusing remote providers unless opted in."""
    if name in ("", DEFAULT_PROVIDER):
        return LocalTemplateProvider()
    if name == OpenAICompatibleProvider.name:
        if not allow_network:
            raise AIError(
                "remote providers are disabled by default; pass --allow-network "
                "to opt in"
            )
        return OpenAICompatibleProvider()
    raise AIError(f"unknown AI provider: {name}")
