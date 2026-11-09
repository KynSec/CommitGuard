"""Heuristic SCA reachability analysis.

A vulnerable dependency is only exploitable when the application actually
imports it.  This module scans first-party source files for import statements
that reference each vulnerable package and annotates the matching findings.

The analysis is intentionally heuristic and offline.  A missing import is
evidence, not proof: unreachable findings are annotated but still reported.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from core.dep_graph import _read_text, _repo_files
from core.scanner import Finding

_MAX_FILES = 5000
_MAX_EVIDENCE = 5
_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".commit_guard",
        "build",
        "commit_guard_reports",
        "dist",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "__pycache__",
    }
)

_LANGUAGE_EXTENSIONS = {
    "python": (".py", ".pyi"),
    "pypi": (".py", ".pyi"),
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "node": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "go": (".go",),
    "maven": (".java", ".kt"),
    "java": (".java", ".kt"),
}

_KNOWN_IMPORT_NAMES = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "attrs": ("attr", "attrs"),
    "protobuf": ("google.protobuf",),
    "opencv-python": ("cv2",),
    "pycryptodome": ("Crypto",),
    "mysqlclient": ("MySQLdb",),
    "psycopg2-binary": ("psycopg2",),
    "pyjwt": ("jwt",),
    "python-dotenv": ("dotenv",),
    "msgpack-python": ("msgpack",),
    "pymupdf": ("fitz",),
    "websocket-client": ("websocket",),
}


class ReachabilityError(RuntimeError):
    """Raised when reachability analysis cannot run."""


@dataclass(frozen=True)
class Reachability:
    package: str
    ecosystem: str
    reachable: bool
    confidence: str
    import_names: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "package": self.package,
            "ecosystem": self.ecosystem,
            "reachable": self.reachable,
            "confidence": self.confidence,
            "import_names": list(self.import_names),
            "evidence": list(self.evidence),
        }


def import_names_for(package: str, ecosystem: str) -> tuple[str, ...]:
    """Returns the import identifiers a package is likely referenced by."""
    name = package.strip()
    eco = ecosystem.strip().lower()
    if not name:
        return ()
    if eco in {"pypi", "python"}:
        base = name.split("[", 1)[0].lower()
        normalized = base.replace("-", "_").replace(".", "_")
        known = _KNOWN_IMPORT_NAMES.get(base) or _KNOWN_IMPORT_NAMES.get(normalized) or ()
        return _unique((*known, normalized))
    if eco in {"npm", "node"}:
        return (name,)
    if eco == "go":
        return _unique((name, name.rsplit("/", 1)[-1]))
    if eco in {"maven", "java"}:
        artifact = name.split(":", 1)[-1]
        return _unique((name, artifact))
    return (name,)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return tuple(seen)


def _escape(value: str) -> str:
    return re.escape(value)


def _patterns(names: Iterable[str], ecosystem: str) -> tuple[re.Pattern[str], ...]:
    eco = ecosystem.strip().lower()
    patterns: list[re.Pattern[str]] = []
    for name in names:
        escaped = _escape(name)
        if eco in {"python", "pypi"}:
            patterns.append(
                re.compile(
                    rf"(?m)^\s*(?:from\s+{escaped}(?:\.|\s+import)|import\s+{escaped}(?:\s|\.|,|$))"
                )
            )
        elif eco in {"npm", "node"}:
            patterns.append(
                re.compile(
                    rf"""(?:from\s*['"]{escaped}(?:/[^'"]*)?['"]|"""
                    rf"""require\(\s*['"]{escaped}(?:/[^'"]*)?['"]\s*\)|"""
                    rf"""import\s*['"]{escaped}(?:/[^'"]*)?['"])"""
                )
            )
        elif eco == "go":
            patterns.append(re.compile(rf"""["']{escaped}(?:/[^"']*)?["']"""))
        elif eco in {"maven", "java"}:
            patterns.append(re.compile(rf"(?m)^\s*import\s+{escaped}(?:\.|;|\s|$)"))
        else:
            patterns.append(re.compile(rf"\b{escaped}\b"))
    return tuple(patterns)


def _source_files(repo_root: Path, ecosystem: str) -> list[Path]:
    extensions = _LANGUAGE_EXTENSIONS.get(ecosystem.strip().lower(), ())
    if not extensions:
        return []
    files: list[Path] = []
    for relative in _repo_files(repo_root)[:_MAX_FILES]:
        path = repo_root / relative
        if path.suffix.lower() not in extensions:
            continue
        if any(part in _EXCLUDED_PARTS for part in Path(relative).parts):
            continue
        files.append(path)
    return files


def assess_package(
    repo_root: Path,
    package: str,
    ecosystem: str,
    *,
    sources: dict[Path, str] | None = None,
) -> Reachability:
    names = import_names_for(package, ecosystem)
    if not names:
        return Reachability(package, ecosystem, False, "low")
    patterns = _patterns(names, ecosystem)
    cache = sources if sources is not None else {}
    evidence: list[str] = []
    for path in _source_files(repo_root, ecosystem):
        text = cache.get(path)
        if text is None:
            text = _read_text(path) or ""
            cache[path] = text
        if not text:
            continue
        if any(pattern.search(text) for pattern in patterns):
            try:
                evidence.append(path.relative_to(repo_root).as_posix())
            except ValueError:
                evidence.append(str(path))
            if len(evidence) >= _MAX_EVIDENCE:
                break
    reachable = bool(evidence)
    return Reachability(
        package=package,
        ecosystem=ecosystem,
        reachable=reachable,
        confidence="high" if reachable else "low",
        import_names=names,
        evidence=tuple(evidence),
    )


def assess_reachability(
    repo_root: Path,
    vulnerabilities: Iterable[object],
) -> dict[str, Reachability]:
    """Assesses every unique package referenced by SCA vulnerabilities.

    Returns a mapping keyed by vulnerability id and by package key.
    """
    results: dict[str, Reachability] = {}
    package_cache: dict[tuple[str, str], Reachability] = {}
    sources: dict[Path, str] = {}
    for vulnerability in vulnerabilities:
        package_name = str(getattr(vulnerability, "package_name", "") or "")
        ecosystem = str(getattr(vulnerability, "ecosystem", "") or "")
        if not package_name:
            continue
        key = (package_name, ecosystem)
        assessment = package_cache.get(key)
        if assessment is None:
            assessment = assess_package(
                repo_root, package_name, ecosystem, sources=sources
            )
            package_cache[key] = assessment
        identifier = str(getattr(vulnerability, "id", "") or "")
        if identifier:
            results[identifier] = assessment
        results[f"{package_name}@{ecosystem}"] = assessment
    return results


def annotate_reachability(
    findings: Iterable[Finding],
    assessments: dict[str, Reachability],
) -> list[Finding]:
    """Adds reachability evidence to dependency findings without filtering them."""
    annotated: list[Finding] = []
    for finding in findings:
        identifier = (
            finding.rule_id.removeprefix("sca-")
        )
        assessment = assessments.get(identifier)
        if assessment is None:
            for alias in finding.aliases:
                assessment = assessments.get(alias)
                if assessment is not None:
                    break
        if assessment is None:
            annotated.append(finding)
            continue
        provenance = dict(finding.provenance or {})
        provenance["reachability"] = assessment.to_dict()
        annotated.append(replace(finding, provenance=provenance))
    return annotated
