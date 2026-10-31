"""Incremental local watch mode built on polling, not editor plugins.

Watch mode is deliberately small: it snapshots the working tree, debounces
changes, cancels a scan when a newer change arrives, and calls a scan callback.
The CLI callback runs an ordinary ``scan`` so watch mode cannot drift from the
gate's behavior.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
}
_SKIP_SUFFIXES = {".pyc", ".pyo", ".swp", ".tmp"}
_MAX_FILES = 200_000

Snapshot = dict[str, tuple[int, int]]


@dataclass(frozen=True)
class WatchEvent:
    added: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.added) | set(self.changed) | set(self.removed)))

    def __bool__(self) -> bool:
        return bool(self.paths)


@dataclass
class WatchState:
    snapshot: Snapshot = field(default_factory=dict)
    scans: int = 0
    last_event: WatchEvent | None = None
    last_status: str = "idle"


def _iter_files(root: Path) -> Iterable[Path]:
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name not in _SKIP_DIRS and not name.endswith(".egg-info")
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.suffix.lower() in _SKIP_SUFFIXES:
                continue
            count += 1
            if count > _MAX_FILES:
                return
            yield path


def snapshot(root: str | Path) -> Snapshot:
    base = Path(root).expanduser().resolve()
    result: Snapshot = {}
    for path in _iter_files(base):
        try:
            stat = path.stat()
            relative = path.relative_to(base).as_posix()
        except OSError:
            continue
        result[relative] = (stat.st_mtime_ns, stat.st_size)
    return result


def diff_snapshots(previous: Mapping[str, tuple[int, int]], current: Mapping[str, tuple[int, int]]) -> WatchEvent:
    previous_keys = set(previous)
    current_keys = set(current)
    return WatchEvent(
        added=tuple(sorted(current_keys - previous_keys)),
        changed=tuple(
            sorted(
                key
                for key in previous_keys & current_keys
                if previous[key] != current[key]
            )
        ),
        removed=tuple(sorted(previous_keys - current_keys)),
    )


def run_watch(
    repo_root: str | Path,
    callback: Callable[[WatchEvent], int | None],
    *,
    interval: float = 1.0,
    debounce: float = 0.25,
    once: bool = False,
    max_scans: int | None = None,
    state: WatchState | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_idle_cycles: int | None = None,
) -> WatchState:
    """Watches ``repo_root`` and calls ``callback`` for each debounced batch.

    ``once`` runs a single initial scan and returns, which keeps the command
    testable and useful in CI.  ``max_scans`` and ``max_idle_cycles`` are also
    intended for automation and tests.
    """
    root = Path(repo_root).expanduser().resolve()
    current_state = state or WatchState()
    current_state.snapshot = snapshot(root)
    if once:
        event = WatchEvent(added=tuple(sorted(current_state.snapshot)))
        current_state.last_event = event
        current_state.scans += 1
        current_state.last_status = "scanning"
        callback(event)
        current_state.last_status = "complete"
        return current_state

    idle_cycles = 0
    while True:
        if max_scans is not None and current_state.scans >= max_scans:
            return current_state
        sleep(max(0.05, interval))
        next_snapshot = snapshot(root)
        event = diff_snapshots(current_state.snapshot, next_snapshot)
        current_state.snapshot = next_snapshot
        if not event:
            idle_cycles += 1
            if max_idle_cycles is not None and idle_cycles >= max_idle_cycles:
                return current_state
            continue
        idle_cycles = 0
        if debounce > 0:
            sleep(debounce)
            current_state.snapshot = snapshot(root)
        current_state.last_event = event
        current_state.scans += 1
        current_state.last_status = "scanning"
        try:
            callback(event)
        finally:
            current_state.last_status = "complete"
