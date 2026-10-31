"""Offline SBOM generation and dependency license discovery.

The SBOM builders are deliberately dependency-free and deterministic apart from
the document identifier and timestamp required by the formats.  They consume
the packages discovered by :mod:`core.sca` and add license data when the
lockfile or local package metadata makes it available.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core import __version__
from core.dep_graph import _read_text, _repo_files
from core.sca import Package, collect_packages

SBOM_FORMATS = ("cyclonedx", "spdx")
UNKNOWN_LICENSE = "NOASSERTION"

_PURL_TYPES = {
    "pypi": "pypi",
    "python": "pypi",
    "npm": "npm",
    "go": "golang",
    "golang": "golang",
    "crates.io": "cargo",
    "cargo": "cargo",
    "rubygems": "gem",
    "ruby": "gem",
    "composer": "composer",
    "maven": "maven",
    "nuget": "nuget",
}

_LICENSE_FIELD_RE = re.compile(
    r"^\s*(?:license|licenses)\s*[:=]\s*(?P<value>.+?)\s*$", re.IGNORECASE
)
_NAME_FIELD_RE = re.compile(r"^\s*Name\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_VERSION_FIELD_RE = re.compile(r"^\s*Version\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_CLASSIFIER_RE = re.compile(r"^\s*Classifier\s*:\s*License\s*::\s*(?P<value>.+?)\s*$")


@dataclass(frozen=True)
class PackageLicense:
    ecosystem: str
    name: str
    version: str
    license: str
    source: str = ""

    @property
    def key(self) -> str:
        return package_key(self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "license": self.license,
            "source": self.source,
        }


def package_key(ecosystem: str, name: str, version: str) -> str:
    return f"{_ecosystem(ecosystem)}:{normalize_name(name)}@{version}"


def normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _ecosystem(value: str) -> str:
    return (value or "unknown").strip().lower()


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _purl_type(ecosystem: str) -> str:
    return _PURL_TYPES.get(_ecosystem(ecosystem), "generic")


def purl(package: Package) -> str:
    name = package.name
    if package.ecosystem.lower() == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{package.version}"
    return f"pkg:{_purl_type(package.ecosystem)}/{name}@{package.version}"


def _license_expression(value: Any) -> str:
    if isinstance(value, str):
        text = value.strip()
        return text or UNKNOWN_LICENSE
    if isinstance(value, (list, tuple)):
        parts = [_license_expression(item) for item in value]
        parts = [part for part in parts if part != UNKNOWN_LICENSE]
        return " AND ".join(parts) if parts else UNKNOWN_LICENSE
    if isinstance(value, Mapping):
        for key in ("id", "name", "expression", "type"):
            if key in value:
                return _license_expression(value[key])
    return UNKNOWN_LICENSE


def _metadata_license(text: str) -> tuple[str, str, str] | None:
    name = ""
    version = ""
    license_value = ""
    classifier_value = ""
    for line in text.splitlines():
        name_match = _NAME_FIELD_RE.match(line)
        if name_match and not name:
            name = name_match.group("value").strip()
        version_match = _VERSION_FIELD_RE.match(line)
        if version_match and not version:
            version = version_match.group("value").strip()
        license_match = _LICENSE_FIELD_RE.match(line)
        if license_match and not license_value:
            license_value = license_match.group("value").strip()
        classifier_match = _CLASSIFIER_RE.match(line)
        if classifier_match and not classifier_value:
            classifier_value = classifier_match.group("value").strip()
    if not name or not version:
        return None
    value = license_value or classifier_value
    return name, version, value or UNKNOWN_LICENSE


def _add_license(
    found: dict[str, PackageLicense],
    ecosystem: str,
    name: str,
    version: str,
    license_value: str,
    source: str,
) -> None:
    if not name:
        return
    value = _license_expression(license_value)
    key = package_key(ecosystem, name, version)
    if key not in found:
        found[key] = PackageLicense(
            ecosystem=_ecosystem(ecosystem),
            name=name,
            version=version,
            license=value,
            source=source,
        )


def _parse_package_lock(
    path: str, text: str, found: dict[str, PackageLicense]
) -> None:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return
    packages = document.get("packages") if isinstance(document, Mapping) else None
    if isinstance(packages, Mapping):
        for location, entry in packages.items():
            if not isinstance(entry, Mapping) or not location:
                continue
            name = str(entry.get("name") or location.rsplit("node_modules/", 1)[-1])
            version = str(entry.get("version") or "")
            if name and version:
                _add_license(
                    found, "npm", name, version, entry.get("license", ""), path
                )
    dependencies = document.get("dependencies") if isinstance(document, Mapping) else None
    if isinstance(dependencies, Mapping):
        _add_locked_dependencies(dependencies, path, found)


def _add_locked_dependencies(
    dependencies: Mapping[str, Any],
    path: str,
    found: dict[str, PackageLicense],
) -> None:
    for name, entry in dependencies.items():
        if not isinstance(entry, Mapping):
            continue
        version = str(entry.get("version") or "")
        if version:
            _add_license(
                found, "npm", str(name), version, entry.get("license", ""), path
            )
        nested = entry.get("dependencies")
        if isinstance(nested, Mapping):
            _add_locked_dependencies(nested, path, found)


def _parse_composer_lock(
    path: str, text: str, found: dict[str, PackageLicense]
) -> None:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(document, Mapping):
        return
    for section in ("packages", "packages-dev"):
        entries = document.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name") or "")
            version = str(entry.get("version") or "").lstrip("v")
            if name and version:
                _add_license(
                    found,
                    "composer",
                    name,
                    version,
                    entry.get("license", ""),
                    path,
                )


def _parse_metadata_file(
    path: str, text: str, found: dict[str, PackageLicense]
) -> None:
    parsed = _metadata_license(text)
    if parsed is None:
        return
    name, version, value = parsed
    lowered = path.lower()
    ecosystem = "PyPI" if ("dist-info/" in lowered or "egg-info/" in lowered) else ""
    if not ecosystem:
        return
    _add_license(found, ecosystem, name, version, value, path)


def collect_licenses(repo_root: str | Path) -> tuple[PackageLicense, ...]:
    """Collects license metadata that is locally available for dependencies."""
    root = Path(repo_root).expanduser().resolve()
    found: dict[str, PackageLicense] = {}
    for path in _repo_files(root):
        lower = path.lower()
        name = Path(path).name.lower()
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            text = _read_text(root / path)
            if text:
                _parse_package_lock(path, text, found)
        elif name == "composer.lock":
            text = _read_text(root / path)
            if text:
                _parse_composer_lock(path, text, found)
        elif name in {"metadata", "pkg-info"} or lower.endswith(
            (".dist-info/metadata", ".egg-info/pkg-info")
        ):
            text = _read_text(root / path)
            if text:
                _parse_metadata_file(path, text, found)
    return tuple(sorted(found.values(), key=lambda item: item.key))


def license_index(
    licenses: Iterable[PackageLicense],
) -> dict[str, PackageLicense]:
    return {item.key: item for item in licenses}


def license_for(
    package: Package, index: Mapping[str, PackageLicense]
) -> str:
    exact = index.get(package_key(package.ecosystem, package.name, package.version))
    if exact is not None:
        return exact.license
    normalized = normalize_name(package.name)
    for item in index.values():
        if (
            normalize_name(item.name) == normalized
            and item.version == package.version
        ):
            return item.license
    return UNKNOWN_LICENSE


def _component(package: Package, license_value: str) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl(package),
        "name": package.name,
        "version": package.version,
        "purl": purl(package),
        "properties": [
            {"name": "commitguard:manifest", "value": package.manifest},
            {"name": "commitguard:ecosystem", "value": package.ecosystem},
        ],
    }
    if license_value and license_value != UNKNOWN_LICENSE:
        if re.fullmatch(r"[A-Za-z0-9.+-]+", license_value):
            component["licenses"] = [{"license": {"id": license_value}}]
        else:
            component["licenses"] = [{"license": {"name": license_value}}]
    return component


def build_cyclonedx(
    packages: Sequence[Package],
    *,
    licenses: Mapping[str, PackageLicense] | None = None,
    project_name: str = "CommitGuard-Project",
    project_version: str = "1.0.0",
    serial: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    index = licenses or {}
    components = [
        _component(package, license_for(package, index)) for package in packages
    ]
    root_ref = f"pkg:generic/{project_name}@{project_version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp
            or _timestamp(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CommitGuard",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": [component["bom-ref"] for component in components],
            }
        ],
    }


def build_spdx(
    packages: Sequence[Package],
    *,
    licenses: Mapping[str, PackageLicense] | None = None,
    project_name: str = "CommitGuard-Project",
    project_version: str = "1.0.0",
    document_namespace: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    index = licenses or {}
    root_id = f"SPDXRef-Package-{re.sub(r'[^A-Za-z0-9.-]+', '-', project_name)}"
    creation = timestamp or _timestamp()
    package_list: list[dict[str, Any]] = [
        {
            "SPDXID": root_id,
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        }
    ]
    relationships: list[dict[str, str]] = []
    for position, package in enumerate(packages, start=1):
        spdx_id = (
            "SPDXRef-Package-"
            + re.sub(r"[^A-Za-z0-9.-]+", "-", package.name)
            + f"-{position}"
        )
        license_value = license_for(package, index)
        declared = (
            license_value
            if license_value and license_value != UNKNOWN_LICENSE
            else "NOASSERTION"
        )
        package_list.append(
            {
                "SPDXID": spdx_id,
                "name": package.name,
                "versionInfo": package.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": declared,
                "sourceInfo": f"Extracted from {package.manifest}",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl(package),
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DEPENDS_ON",
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name} SBOM",
        "documentNamespace": document_namespace
        or f"https://commitguard.local/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": creation,
            "creators": [f"Tool: CommitGuard-{__version__}"],
        },
        "packages": package_list,
        "relationships": relationships,
    }


def build_sbom(
    repo_root: str | Path,
    *,
    fmt: str = "cyclonedx",
    project_name: str | None = None,
    project_version: str = "1.0.0",
    packages: Sequence[Package] | None = None,
    licenses: Iterable[PackageLicense] | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).expanduser().resolve()
    selected = fmt.strip().lower()
    if selected not in SBOM_FORMATS:
        raise ValueError(
            f"unsupported SBOM format {fmt!r}; expected {', '.join(SBOM_FORMATS)}"
        )
    discovered = tuple(packages or collect_packages(root))
    index = license_index(licenses or collect_licenses(root))
    name = project_name or root.name or "CommitGuard-Project"
    if selected == "spdx":
        return build_spdx(
            discovered,
            licenses=index,
            project_name=name,
            project_version=project_version,
        )
    return build_cyclonedx(
        discovered,
        licenses=index,
        project_name=name,
        project_version=project_version,
    )


def write_sbom(document: Mapping[str, Any], output: str | Path) -> Path:
    target = Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    return target
