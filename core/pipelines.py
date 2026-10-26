"""Project-local delivery pipelines for the control center.

Pipelines are explicit argv arrays read from ``.commit_guard.toml``.  They
never go through a shell, are confined to the repository, and are only started
by a direct user action in the local GUI or through the command API.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
MAX_OUTPUT_CHARS = 120_000
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CATEGORIES = ("test", "lint", "typecheck", "build", "security", "deploy", "custom")
_ACTIVE: set[str] = set()
_ACTIVE_LOCK = threading.Lock()


class PipelineError(ValueError):
    """Raised for invalid pipeline configuration or execution state."""


@dataclass(frozen=True)
class PipelineSpec:
    name: str
    command: tuple[str, ...]
    description: str = ""
    category: str = "custom"
    cwd: str = "."
    timeout: int = DEFAULT_TIMEOUT
    env: dict[str, str] = field(default_factory=dict, repr=False)
    source: str = "configured"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "display_command": shlex.join(self.command),
            "description": self.description,
            "category": self.category,
            "cwd": self.cwd,
            "timeout": self.timeout,
            "env_keys": sorted(self.env),
            "source": self.source,
        }


@dataclass(frozen=True)
class PipelineResult:
    name: str
    command: tuple[str, ...]
    source: str
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    output: str
    timed_out: bool = False
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "display_command": shlex.join(self.command),
            "source": self.source,
            "exit_code": self.exit_code,
            "ok": self.exit_code == 0 and not self.timed_out,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output": self.output,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise PipelineError(f"could not read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PipelineError(f"invalid TOML in {path}: {exc}") from exc
    return data


def _command(value: object, name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            parts = shlex.split(value)
        except ValueError as exc:
            raise PipelineError(f"pipeline {name!r} has an invalid command: {exc}") from exc
    elif isinstance(value, (list, tuple)):
        parts = [str(item) for item in value]
    else:
        raise PipelineError(f"pipeline {name!r} command must be a string or array")
    if not parts:
        raise PipelineError(f"pipeline {name!r} command is empty")
    if any("\x00" in part or "\n" in part or "\r" in part for part in parts):
        raise PipelineError(f"pipeline {name!r} command contains a control character")
    return tuple(parts)


def _timeout(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise PipelineError(f"pipeline {name!r} timeout must be a number")
    if isinstance(value, int):
        timeout = value
    elif isinstance(value, str):
        try:
            timeout = int(value)
        except ValueError as exc:
            raise PipelineError(f"pipeline {name!r} timeout must be a number") from exc
    else:
        raise PipelineError(f"pipeline {name!r} timeout must be a number")
    if timeout < 1 or timeout > MAX_TIMEOUT:
        raise PipelineError(
            f"pipeline {name!r} timeout must be between 1 and {MAX_TIMEOUT} seconds"
        )
    return timeout


def _env(value: object, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PipelineError(f"pipeline {name!r} env must be a table")
    result: dict[str, str] = {}
    for key, item in value.items():
        text_key = str(key)
        if not _ENV_KEY_RE.match(text_key):
            raise PipelineError(f"pipeline {name!r} has an invalid env key {text_key!r}")
        text_value = str(item)
        if "\x00" in text_value:
            raise PipelineError(f"pipeline {name!r} env {text_key!r} contains NUL")
        result[text_key] = text_value
    return result


def _cwd(value: object, name: str, repo_root: Path) -> str:
    text = str(value or ".").strip()
    if not text:
        return "."
    candidate = Path(text)
    if "\x00" in text:
        raise PipelineError(f"pipeline {name!r} cwd contains NUL")
    resolved = candidate.resolve() if candidate.is_absolute() else (repo_root / candidate).resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError as exc:
        raise PipelineError(f"pipeline {name!r} cwd escapes the repository") from exc
    return str(candidate)


def _spec(
    name: str,
    value: object,
    repo_root: Path,
    *,
    source: str = "configured",
) -> PipelineSpec:
    if not _NAME_RE.match(name):
        raise PipelineError(
            "pipeline names must start with a letter or number and contain only "
            "letters, numbers, '.', '_', or '-'"
        )
    if isinstance(value, dict):
        command_value = value.get("command")
        description = str(value.get("description") or "")
        category = str(value.get("category") or "custom").strip().lower() or "custom"
        if category not in _CATEGORIES:
            raise PipelineError(
                f"pipeline {name!r} category must be one of {', '.join(_CATEGORIES)}"
            )
        cwd_value = value.get("cwd", ".")
        timeout_value = value.get("timeout", DEFAULT_TIMEOUT)
        env_value = value.get("env")
    else:
        command_value = value
        description = ""
        category = "custom"
        cwd_value = "."
        timeout_value = DEFAULT_TIMEOUT
        env_value = None
    if command_value is None:
        raise PipelineError(f"pipeline {name!r} is missing command")
    return PipelineSpec(
        name=name,
        command=_command(command_value, name),
        description=description,
        category=category,
        cwd=_cwd(cwd_value, name, repo_root),
        timeout=_timeout(timeout_value, name),
        env=_env(env_value, name),
        source=source,
    )


def load_pipelines(
    repo_root: str | Path,
    *,
    config_path: str | Path | None = None,
) -> dict[str, PipelineSpec]:
    root = Path(repo_root).expanduser().resolve()
    path = Path(config_path) if config_path is not None else root / ".commit_guard.toml"
    if not path.is_file():
        return {}
    raw = _load_toml(path)
    section = raw.get("pipelines", {})
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise PipelineError("[pipelines] must be a TOML table")
    specs: dict[str, PipelineSpec] = {}
    for name, value in section.items():
        specs[str(name)] = _spec(str(name), value, root)
    return dict(sorted(specs.items()))


def _python_has(repo: Path, needle: str) -> bool:
    for filename in ("pyproject.toml", "setup.cfg", "setup.py", "requirements.txt"):
        path = repo / filename
        if not path.is_file():
            continue
        try:
            if needle.lower() in path.read_text(encoding="utf-8", errors="ignore").lower():
                return True
        except OSError:
            continue
    return False


def _make_targets(repo: Path) -> set[str]:
    path = repo / "Makefile"
    if not path.is_file():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()
    return set(re.findall(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", text, re.MULTILINE))  # commit-guard-ignore: template-explicit-unescape


def _detected_spec(
    name: str,
    command: list[str],
    category: str,
    description: str,
) -> PipelineSpec:
    return PipelineSpec(
        name=name,
        command=tuple(command),
        description=description,
        category=category if category in _CATEGORIES else "custom",
        source="detected",
    )


def detect_pipelines(repo_root: str | Path) -> dict[str, PipelineSpec]:
    root = Path(repo_root).expanduser().resolve()
    found: dict[str, PipelineSpec] = {}

    def add(name: str, command: list[str], category: str, description: str) -> None:
        found.setdefault(name, _detected_spec(name, command, category, description))

    tests = root / "tests"
    pyproject = root / "pyproject.toml"
    if tests.is_dir() or pyproject.is_file():
        if (
            _python_has(root, "pytest")
            or (root / "pytest.ini").is_file()
            or (root / "conftest.py").is_file()
            or (tests / "conftest.py").is_file()
        ):
            add("python-test", ["python", "-m", "pytest"], "test", "Run the Python test suite with pytest.")
        elif tests.is_dir():
            add(
                "python-test",
                ["python", "-m", "unittest", "discover", "-s", "tests"],
                "test",
                "Run the Python unittest suite.",
            )
    if _python_has(root, "ruff") or (root / ".ruff.toml").is_file() or (root / "ruff.toml").is_file():
        add("python-lint", ["python", "-m", "ruff", "check", "."], "lint", "Lint Python sources with Ruff.")
    if _python_has(root, "mypy") or (root / "mypy.ini").is_file():
        add("python-types", ["python", "-m", "mypy", "."], "typecheck", "Type-check Python sources with mypy.")
    if pyproject.is_file():
        add("python-build", ["python", "-m", "build"], "build", "Build the Python sdist and wheel.")

    package = root / "package.json"
    if package.is_file():
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts", {})
        except (OSError, ValueError, AttributeError):
            scripts = {}
        if isinstance(scripts, dict):
            for script in ("test", "lint", "build", "typecheck", "check"):
                if script in scripts:
                    add(
                        f"node-{script}",
                        ["npm", "run", script],
                        "test" if script == "test" else ("build" if script == "build" else "lint"),
                        f"Run the package.json {script!r} script.",
                    )

    make_targets = _make_targets(root)
    for target in ("test", "lint", "build", "check"):
        if target in make_targets:
            add(
                f"make-{target}",
                ["make", target],
                "test" if target == "test" else ("build" if target == "build" else "lint"),
                f"Run the Makefile target {target!r}.",
            )

    if (root / "Dockerfile").is_file():
        slug = re.sub(r"[^a-z0-9_.-]+", "-", root.name.lower()).strip("-") or "app"
        add("docker-build", ["docker", "build", "-t", f"{slug}:local", "."], "build", "Build the local Docker image.")
    if (root / "docker-compose.yml").is_file() or (root / "compose.yaml").is_file():
        add("compose-validate", ["docker", "compose", "config", "-q"], "build", "Validate the Compose configuration.")

    return dict(sorted(found.items()))


def list_pipelines(repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root).expanduser().resolve()
    configured = load_pipelines(root)
    detected = detect_pipelines(root)
    suggestions = {
        name: spec for name, spec in detected.items() if name not in configured
    }
    return {
        "configured": [spec.to_dict() for spec in configured.values()],
        "detected": [spec.to_dict() for spec in suggestions.values()],
        "total": len(configured) + len(suggestions),
    }


def _truncate(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text, False
    return "[output truncated to the final 120000 characters]\n" + text[-MAX_OUTPUT_CHARS:], True


def _find_spec(repo_root: Path, name: str) -> PipelineSpec:
    if not _NAME_RE.match(name):
        raise PipelineError(f"invalid pipeline name: {name!r}")
    configured = load_pipelines(repo_root)
    if name in configured:
        return configured[name]
    detected = detect_pipelines(repo_root)
    if name in detected:
        return detected[name]
    raise PipelineError(f"unknown pipeline: {name!r}")


def run_pipeline(repo_root: str | Path, name: str) -> PipelineResult:
    root = Path(repo_root).expanduser().resolve()
    spec = _find_spec(root, name)
    key = f"{root}:{name}"
    with _ACTIVE_LOCK:
        if key in _ACTIVE:
            raise PipelineError(f"pipeline {name!r} is already running")
        _ACTIVE.add(key)
    cwd = Path(spec.cwd)
    if not cwd.is_absolute():
        cwd = (root / cwd).resolve()
    try:
        cwd.relative_to(root)
    except ValueError as exc:
        _ACTIVE.discard(key)
        raise PipelineError(f"pipeline {name!r} cwd escapes the repository") from exc
    if not cwd.is_dir():
        _ACTIVE.discard(key)
        raise PipelineError(f"pipeline {name!r} cwd does not exist: {cwd}")

    env = os.environ.copy()
    env.update(spec.env)
    started = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    code = 1
    kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "errors": "replace",
    }
    if os.name != "nt":  # commit-guard-ignore: template-explicit-unescape
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(list(spec.command), **kwargs)
        try:
            stdout, stderr = process.communicate(timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name != "nt":  # commit-guard-ignore: template-explicit-unescape
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:  # pragma: no cover - Windows branch
                process.kill()
            stdout, stderr = process.communicate()
        code = int(process.returncode if process.returncode is not None else 1)
    except FileNotFoundError:
        stderr = f"command not found: {spec.command[0]}"
        code = 127
    except OSError as exc:
        stderr = str(exc)
        code = 126
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.discard(key)

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, out_truncated = _truncate(stdout or "")
    stderr, err_truncated = _truncate(stderr or "")
    output = stdout
    if stderr:
        output = (output + ("\n" if output else "") + stderr).strip()
    return PipelineResult(
        name=name,
        command=spec.command,
        source=spec.source,
        exit_code=124 if timed_out else code,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
        output=output,
        timed_out=timed_out,
        truncated=out_truncated or err_truncated,
    )
