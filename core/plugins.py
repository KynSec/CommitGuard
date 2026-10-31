"""Out-of-process plugin protocol.

Plugins are untrusted.  CommitGuard loads them only from an explicit directory,
verifies an optional manifest digest before execution, runs them without a
shell, and applies timeout, output-size, and category limits.  A plugin crash
or invalid response is isolated from the scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from core.findings import FindingSchemaError, extract_findings
from core.scanner import Finding

PROTOCOL_VERSION = 1
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PLUGIN_FINDINGS = 10_000
DEFAULT_PLUGIN_DIR = Path.home() / ".config" / "commitguard" / "plugins"


class PluginError(RuntimeError):
    """Raised when a plugin manifest, signature, or execution is invalid."""


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    entrypoint: Path
    directory: Path
    description: str = ""
    capabilities: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "entrypoint": str(self.entrypoint),
            "directory": str(self.directory),
            "description": self.description,
            "capabilities": list(self.capabilities),
            "permissions": list(self.permissions),
            "signature": self.signature,
        }


@dataclass(frozen=True)
class PluginResult:
    manifest: PluginManifest
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _manifest_path(directory: Path) -> Path | None:
    for name in ("plugin.json", "plugin.yaml", "plugin.yml", "manifest.json"):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def load_manifest(path: str | Path) -> PluginManifest:
    manifest_path = Path(path).expanduser()
    directory = manifest_path.parent.resolve()
    if not manifest_path.is_file():
        raise PluginError(f"plugin manifest not found: {manifest_path}")
    try:
        text = manifest_path.read_text(encoding="utf-8")
        document = (
            json.loads(text)
            if manifest_path.suffix.lower() == ".json"
            else yaml.safe_load(text)
        )
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise PluginError(f"invalid plugin manifest {manifest_path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise PluginError(f"plugin manifest {manifest_path} must be an object")
    name = str(document.get("name") or "").strip()
    entrypoint_value = str(document.get("entrypoint") or "").strip()
    if not name:
        raise PluginError("plugin manifest is missing name")
    if not entrypoint_value:
        raise PluginError("plugin manifest is missing entrypoint")
    entrypoint = (directory / entrypoint_value).resolve()
    try:
        entrypoint.relative_to(directory)
    except ValueError as exc:
        raise PluginError("plugin entrypoint escapes its plugin directory") from exc
    if not entrypoint.is_file():
        raise PluginError(f"plugin entrypoint not found: {entrypoint}")
    permissions = _strings(document.get("permissions"))
    allowed_permissions = {"network", "filesystem-read", "filesystem-write"}
    unknown = set(permissions) - allowed_permissions
    if unknown:
        raise PluginError(
            f"unknown plugin permission(s): {', '.join(sorted(unknown))}"
        )
    if "network" in permissions:
        raise PluginError(
            "plugins may not request network access in plugin API v1"
        )
    return PluginManifest(
        name=name,
        version=str(document.get("version") or "0.0.0"),
        entrypoint=entrypoint,
        directory=directory,
        description=str(document.get("description") or ""),
        capabilities=_strings(document.get("capabilities")),
        permissions=permissions,
        signature=str(
            document.get("signature")
            or document.get("sha256")
            or document.get("signature_sha256")
            or ""
        ),
    )


def discover_plugins(
    directory: str | Path | None = None,
    *,
    recursive: bool = False,
) -> tuple[PluginManifest, ...]:
    base = Path(directory).expanduser() if directory else DEFAULT_PLUGIN_DIR
    if not base.is_dir():
        return ()
    candidates = (
        [base, *base.rglob("*")]
        if recursive
        else [base, *base.iterdir()]
    )
    manifests: list[PluginManifest] = []
    seen: set[Path] = set()
    for candidate in sorted(candidates, key=lambda item: str(item)):
        if not candidate.is_dir():
            continue
        path = _manifest_path(candidate)
        if path is None:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        manifests.append(load_manifest(path))
    return tuple(manifests)


def manifest_digest(manifest: PluginManifest) -> str:
    return hashlib.sha256(manifest.entrypoint.read_bytes()).hexdigest()


def verify_manifest(
    manifest: PluginManifest,
    *,
    allow_unsigned: bool = False,
) -> tuple[bool, str]:
    if not manifest.signature:
        if allow_unsigned:
            return True, "unsigned plugin allowed by explicit flag"
        return False, "plugin is unsigned; pass --allow-unsigned-plugin"
    try:
        digest = manifest_digest(manifest)
    except OSError as exc:
        return False, f"could not read plugin entrypoint: {exc}"
    expected = manifest.signature.strip().lower()
    if expected.startswith("sha256:"):
        expected = expected.split(":", 1)[1]
    if digest != expected:
        return False, "plugin signature does not match the entrypoint digest"
    return True, "signature verified"


def _plugin_findings(
    payload: Any, manifest: PluginManifest
) -> tuple[Finding, ...]:
    try:
        findings = extract_findings(payload)
    except (FindingSchemaError, TypeError, ValueError) as exc:
        raise PluginError(f"plugin returned invalid findings: {exc}") from exc
    if len(findings) > MAX_PLUGIN_FINDINGS:
        raise PluginError("plugin returned too many findings")
    allowed = {capability.lower() for capability in manifest.capabilities}
    if allowed:
        for finding in findings:
            if finding.category and finding.category.lower() not in allowed:
                raise PluginError(
                    f"plugin emitted category {finding.category!r} outside its capabilities"
                )
    engine = f"plugin:{manifest.name}"
    return tuple(
        replace(finding, engine=engine, source=engine) for finding in findings
    )


def run_plugin(
    manifest: PluginManifest,
    *,
    context: Mapping[str, Any] | None = None,
    timeout: float = 30.0,
    allow_unsigned: bool = False,
) -> PluginResult:
    import time

    started = time.monotonic()
    verified, reason = verify_manifest(manifest, allow_unsigned=allow_unsigned)
    if not verified:
        return PluginResult(
            manifest=manifest,
            errors=(reason,),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    request = {
        "protocol": PROTOCOL_VERSION,
        "action": "scan",
        "plugin": {"name": manifest.name, "version": manifest.version},
        "context": dict(context or {}),
    }
    command = (
        [sys.executable, str(manifest.entrypoint)]
        if manifest.entrypoint.suffix.lower() == ".py"
        else [str(manifest.entrypoint)]
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONIOENCODING": "utf-8",
        "COMMITGUARD_PLUGIN": "1",
    }
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(request),
            cwd=str(manifest.directory),
            env=environment,
            text=True,
            errors="replace",
            capture_output=True,
            timeout=max(0.1, timeout),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PluginResult(
            manifest=manifest,
            errors=(f"plugin timed out after {timeout:.1f}s",),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except OSError as exc:
        return PluginResult(
            manifest=manifest,
            errors=(f"plugin could not start: {exc}",),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    duration = int((time.monotonic() - started) * 1000)
    if len(completed.stdout.encode("utf-8", "replace")) > MAX_OUTPUT_BYTES:
        return PluginResult(
            manifest=manifest,
            errors=("plugin output exceeded the 4 MiB limit",),
            duration_ms=duration,
        )
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip().splitlines()
        message = detail[-1] if detail else f"exit code {completed.returncode}"
        return PluginResult(
            manifest=manifest,
            errors=(f"plugin failed: {message}",),
            duration_ms=duration,
        )
    try:
        payload = json.loads(completed.stdout or "[]")
        findings = _plugin_findings(payload, manifest)
    except (json.JSONDecodeError, PluginError) as exc:
        return PluginResult(
            manifest=manifest,
            errors=(str(exc),),
            duration_ms=duration,
        )
    warnings = tuple(
        line.strip()
        for line in (completed.stderr or "").splitlines()
        if line.strip()
    )
    return PluginResult(
        manifest=manifest,
        findings=findings,
        warnings=warnings,
        duration_ms=duration,
    )


def run_plugins(
    manifests: Iterable[PluginManifest],
    *,
    context: Mapping[str, Any] | None = None,
    timeout: float = 30.0,
    allow_unsigned: bool = False,
) -> tuple[PluginResult, ...]:
    results: list[PluginResult] = []
    for manifest in manifests:
        try:
            results.append(
                run_plugin(
                    manifest,
                    context=context,
                    timeout=timeout,
                    allow_unsigned=allow_unsigned,
                )
            )
        except Exception as exc:  # noqa: BLE001 - plugin isolation is the contract
            results.append(
                PluginResult(
                    manifest=manifest,
                    errors=(f"{type(exc).__name__}: {exc}",),
                )
            )
    return tuple(results)
