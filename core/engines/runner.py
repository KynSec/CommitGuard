"""Engine registry and isolated parallel runner."""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field, replace

from core.engines.base import (
    Engine,
    EngineCapability,
    EngineResult,
    RegisteredEngine,
    ScanContext,
)
from core.engines.normalize import dedupe_findings
from core.scanner import Finding


@dataclass
class Registry:
    _engines: dict[str, RegisteredEngine] = field(default_factory=dict)

    def register(
        self,
        engine: Engine,
        *,
        enabled: bool = True,
        required: bool = False,
        timeout: float | None = None,
    ) -> None:
        self._engines[engine.name] = RegisteredEngine(
            engine=engine,
            enabled=enabled,
            required=required,
            timeout=timeout,
        )

    def unregister(self, name: str) -> None:
        self._engines.pop(name, None)

    def get(self, name: str) -> RegisteredEngine | None:
        return self._engines.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(self._engines)

    def capabilities(self) -> tuple[EngineCapability, ...]:
        return tuple(entry.engine.capability() for entry in self._engines.values())

    def selected(
        self, names: list[str] | tuple[str, ...] | None = None
    ) -> tuple[RegisteredEngine, ...]:
        if names is None:
            return tuple(entry for entry in self._engines.values() if entry.enabled)
        unknown = [name for name in names if name not in self._engines]
        if unknown:
            raise KeyError(f"unknown engine(s): {', '.join(unknown)}")
        return tuple(self._engines[name] for name in names if self._engines[name].enabled)


def default_registry() -> Registry:
    from core.engines.regex_engine import RegexEngine
    from core.engines.taint_engine import TaintEngine

    registry = Registry()
    registry.register(RegexEngine())
    registry.register(TaintEngine())
    return registry


@dataclass(frozen=True)
class RunReport:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    durations_ms: dict[str, int]
    engines: tuple[str, ...]
    cancelled: bool = False

    def result(self) -> EngineResult:
        return EngineResult(
            findings=self.findings,
            warnings=self.warnings,
            errors=self.errors,
            duration_ms=sum(self.durations_ms.values()),
            engine="runner",
        )


class Runner:
    def __init__(self, registry: Registry | None = None, *, workers: int = 1):
        self.registry = registry or default_registry()
        self.workers = max(1, int(workers))

    def _run_one(
        self, entry: RegisteredEngine, context: ScanContext
    ) -> EngineResult:
        started = time.perf_counter()
        try:
            result = entry.engine.run(context)
        except Exception as exc:  # noqa: BLE001 - engine isolation is the contract
            return EngineResult(
                errors=(f"{entry.name}: {type(exc).__name__}: {exc}",),
                duration_ms=int((time.perf_counter() - started) * 1000),
                engine=entry.name,
            )
        if not isinstance(result, EngineResult):
            return EngineResult(
                errors=(f"{entry.name}: engine returned an invalid result",),
                duration_ms=int((time.perf_counter() - started) * 1000),
                engine=entry.name,
            )
        return replace(
            result,
            duration_ms=max(
                result.duration_ms, int((time.perf_counter() - started) * 1000)
            ),
            engine=entry.name,
        )

    def run(
        self,
        context: ScanContext,
        names: list[str] | tuple[str, ...] | None = None,
    ) -> RunReport:
        started = time.perf_counter()
        selected = self.registry.selected(names)
        warnings: list[str] = []
        errors: list[str] = []
        durations: dict[str, int] = {}
        findings: list[Finding] = []
        completed: set[str] = set()
        cancelled = False

        runnable: list[RegisteredEngine] = []
        for entry in selected:
            available, reason = entry.engine.available()
            if not available:
                message = f"{entry.name}: unavailable ({reason})"
                if entry.required:
                    errors.append(message)
                else:
                    warnings.append(message)
                continue
            runnable.append(entry)

        if self.workers == 1:
            for entry in runnable:
                if context.cancelled():
                    cancelled = True
                    warnings.append("scan deadline reached")
                    break
                result = self._run_one(entry, context)
                self._collect(entry, result, findings, warnings, errors, durations)
                completed.add(entry.name)
        else:
            executor = ThreadPoolExecutor(max_workers=self.workers)
            futures: dict[Future[EngineResult], RegisteredEngine] = {
                executor.submit(self._run_one, entry, context): entry
                for entry in runnable
            }
            for future, entry in futures.items():
                remaining = context.deadline_remaining()
                timeout = entry.timeout or context.engine_timeout
                if remaining is not None:
                    timeout = min(timeout, remaining)
                try:
                    result = future.result(timeout=max(0.001, timeout))
                except FutureTimeout:
                    cancelled = True
                    warnings.append(f"{entry.name}: timed out after {timeout:.1f}s")
                    future.cancel()
                    continue
                except Exception as exc:  # noqa: BLE001 - pragma: no cover
                    errors.append(f"{entry.name}: {type(exc).__name__}: {exc}")
                    continue
                self._collect(entry, result, findings, warnings, errors, durations)
                completed.add(entry.name)
            executor.shutdown(wait=False, cancel_futures=True)

        merged = dedupe_findings(findings)
        if context.max_findings and len(merged) > context.max_findings:
            merged = merged[: context.max_findings]
        durations["_total"] = int((time.perf_counter() - started) * 1000)
        return RunReport(
            findings=tuple(merged),
            warnings=tuple(warnings),
            errors=tuple(errors),
            durations_ms=durations,
            engines=tuple(sorted(completed)),
            cancelled=cancelled,
        )

    @staticmethod
    def _collect(
        entry: RegisteredEngine,
        result: EngineResult,
        findings: list[Finding],
        warnings: list[str],
        errors: list[str],
        durations: dict[str, int],
    ) -> None:
        findings.extend(result.findings)
        warnings.extend(f"{entry.name}: {warning}" for warning in result.warnings)
        errors.extend(result.errors)
        if entry.required and result.errors:
            errors.extend(f"{entry.name}: required engine failed")
        durations[entry.name] = result.duration_ms
