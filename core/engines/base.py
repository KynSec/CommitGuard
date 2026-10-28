"""Engine protocol and shared scan context."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from core.git_diff import DiffLine
from core.rule_loader import Rule
from core.scanner import Finding


@dataclass(frozen=True)
class EngineCapability:
    name: str
    languages: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    supports_fixes: bool = False
    supports_flows: bool = False
    requires_network: bool = False
    requires_binary: bool = False
    version: str = "unknown"


@dataclass(frozen=True)
class EngineResult:
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    duration_ms: int = 0
    engine: str = "unknown"


@dataclass(frozen=True)
class ScanContext:
    """Everything an engine may inspect.  Engines must not scan outside it."""

    repo_root: Path
    diff_lines: tuple[DiffLine, ...] = ()
    changed_paths: tuple[str, ...] = ()
    files: dict[str, list[str]] | None = None
    rules: tuple[Rule, ...] = ()
    line_allowlist: tuple[re.Pattern[str], ...] = ()
    path_allowlist: tuple[re.Pattern[str], ...] = ()
    path_excludes: tuple[str, ...] = ()
    ignore_inline: bool = True
    ignored_files: frozenset[str] = frozenset()
    ignored_rule_ids: frozenset[str] = frozenset()
    filter_placeholders: bool = True
    max_findings: int = 0
    file_lines: dict[str, list[str]] | None = None
    severity_overrides: dict[str, str] = field(default_factory=dict)
    detect_ignore_file: bool = True
    deadline_at: float | None = None
    workers: int = 1
    engine_timeout: float = 120.0
    options: dict[str, object] = field(default_factory=dict)

    @property
    def python_paths(self) -> tuple[str, ...]:
        return tuple(
            path for path in self.changed_paths if path.lower().endswith((".py", ".pyi"))
        )

    def deadline_remaining(self) -> float | None:
        if self.deadline_at is None:
            return None
        return max(0.0, self.deadline_at - time.monotonic())

    def cancelled(self) -> bool:
        return self.deadline_at is not None and time.monotonic() >= self.deadline_at


@runtime_checkable
class Engine(Protocol):
    name: str

    def capability(self) -> EngineCapability: ...

    def available(self) -> tuple[bool, str]: ...

    def run(self, context: ScanContext) -> EngineResult: ...


@dataclass
class RegisteredEngine:
    engine: Engine
    enabled: bool = True
    required: bool = False
    timeout: float | None = None

    @property
    def name(self) -> str:
        return self.engine.name
