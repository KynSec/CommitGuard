"""Detection engine protocol, registry, and built-in adapters."""

from core.engines.base import (
    Engine,
    EngineCapability,
    EngineResult,
    RegisteredEngine,
    ScanContext,
)
from core.engines.normalize import dedupe_findings, stable_order
from core.engines.regex_engine import RegexEngine
from core.engines.runner import Registry, Runner, RunReport, default_registry
from core.engines.taint_engine import TaintEngine

__all__ = [
    "Engine",
    "EngineCapability",
    "EngineResult",
    "RegexEngine",
    "RegisteredEngine",
    "Registry",
    "RunReport",
    "Runner",
    "ScanContext",
    "TaintEngine",
    "dedupe_findings",
    "default_registry",
    "stable_order",
]
