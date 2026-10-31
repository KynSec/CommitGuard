"""Optional Semgrep/Opengrep adapter.

The engine is never enabled implicitly by the CLI: Semgrep rules carry their
own license and running a second scanner changes the result set.  Callers opt
in by configuring a rule path and registering the engine.  A missing binary is
reported as unavailable, never as a scan failure.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from core.engines.base import EngineCapability, EngineResult, ScanContext
from core.ingest import IngestError, ingest_semgrep

SEVERITY = ("critical", "high", "medium", "low", "info")


class SemgrepEngine:
    name = "semgrep"

    def __init__(
        self,
        *,
        executable: str | None = None,
        config: str | Path | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.executable = executable or os.environ.get("COMMITGUARD_SEMGREP", "")
        self.config = str(config) if config else os.environ.get(
            "COMMITGUARD_SEMGREP_CONFIG", ""
        )
        self.timeout = max(1.0, timeout)

    def _binary(self) -> str:
        if self.executable:
            if Path(self.executable).expanduser().is_file():
                return str(Path(self.executable).expanduser())
            return shutil.which(self.executable) or ""
        for candidate in ("semgrep", "opengrep"):
            found = shutil.which(candidate)
            if found:
                return found
        return ""

    def capability(self) -> EngineCapability:
        return EngineCapability(
            name=self.name,
            categories=frozenset({"sast", "secret", "supply-chain"}),  # commit-guard-ignore: generic-api-key
            supports_fixes=True,
            supports_flows=True,
            requires_binary=True,
        )

    def available(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "semgrep/opengrep binary not found"
        if not self.config:
            return False, "set COMMITGUARD_SEMGREP_CONFIG to a local rule path"
        if not Path(self.config).exists():
            return False, f"semgrep config not found: {self.config}"
        return True, binary

    def run(self, context: ScanContext) -> EngineResult:
        available, reason = self.available()
        if not available:
            return EngineResult(warnings=(reason,), engine=self.name)
        binary = reason
        paths = [
            path
            for path in context.changed_paths
            if (context.repo_root / path).is_file()
        ]
        if not paths:
            return EngineResult(engine=self.name)
        command = [
            binary,
            "scan",
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
            "--config",
            self.config,
            *paths,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=str(context.repo_root),
                text=True,
                capture_output=True,
                timeout=min(self.timeout, context.engine_timeout),
                check=False,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", ""),
                    "SEMGREP_SEND_METRICS": "off",
                },
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                errors=("semgrep: timed out",), engine=self.name
            )
        except OSError as exc:
            return EngineResult(
                warnings=(f"semgrep: could not start: {exc}",), engine=self.name
            )
        if completed.returncode not in (0, 1):
            detail = (completed.stderr or "").strip().splitlines()
            return EngineResult(
                errors=(
                    (
                        f"semgrep: exit {completed.returncode}: "
                        f"{detail[-1] if detail else 'unknown error'}"
                    ),
                ),
                engine=self.name,
            )
        try:
            document = json.loads(completed.stdout or "{}")
            findings = ingest_semgrep(document, repo_root=context.repo_root)
        except (json.JSONDecodeError, IngestError) as exc:
            return EngineResult(
                errors=(f"semgrep: invalid output: {exc}",), engine=self.name
            )
        return EngineResult(findings=tuple(findings), engine=self.name)
