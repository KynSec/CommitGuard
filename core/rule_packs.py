"""Signed third-party rule packs and a git-based community registry.

A rule pack is a directory containing a manifest (``pack.json`` or
``pack.yaml``) and one or more YAML rule files in CommitGuard's custom rule
format.  Packs are signed with an HMAC-SHA256 sidecar (``pack.sig``) so a
downloaded pack can be verified before it is copied into ``rules/custom``.

The registry is a plain git repository with a ``registry.json`` file.  There is
no hosted service: teams can mirror, fork, or pin a registry commit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

SIGNING_KEY_ENV = "COMMIT_GUARD_RULE_PACK_KEY"  # commit-guard-ignore
SIGNATURE_FILENAME = "pack.sig"
SIGNATURE_PREFIX = "hmac-sha256:"
MANIFEST_NAMES = ("pack.json", "pack.yaml", "pack.yml")
REGISTRY_FILENAME = "registry.json"
DEFAULT_PACK_DIR = Path.home() / ".config" / "commitguard" / "rule-packs"
_GIT_TIMEOUT = 120


class RulePackError(RuntimeError):
    """Raised when a rule pack or registry entry is invalid."""


@dataclass(frozen=True)
class RulePack:
    name: str
    version: str
    directory: Path
    rules_file: Path
    description: str = ""
    license: str = ""
    source_url: str = ""
    source_commit: str = ""
    signature: str = ""
    digest: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "license": self.license,
            "source": self.source_url,
            "commit": self.source_commit,
            "rules_file": str(self.rules_file),
            "signature": self.signature,
            "digest": self.digest,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class RegistryEntry:
    name: str
    version: str
    source: str
    path: str = ""
    digest: str = ""
    signature: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "path": self.path,
            "digest": self.digest,
            "signature": self.signature,
            "description": self.description,
        }


@dataclass(frozen=True)
class RulePackRegistry:
    source: str
    entries: tuple[RegistryEntry, ...] = ()

    def find(self, name: str) -> RegistryEntry:
        for entry in self.entries:
            if entry.name == name:
                return entry
        raise RulePackError(f"rule pack '{name}' is not present in the registry")


def _read_document(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RulePackError(f"could not read '{path}': {exc}") from exc
    try:
        if path.suffix.lower() == ".json":
            document = json.loads(text)
        else:
            document = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise RulePackError(f"invalid pack manifest '{path}': {exc}") from exc
    if not isinstance(document, dict):
        raise RulePackError(f"pack manifest '{path}' must be an object")
    return document


def _manifest_path(path: Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_file():
        return candidate
    if candidate.is_dir():
        for name in MANIFEST_NAMES:
            manifest = candidate / name
            if manifest.is_file():
                return manifest
    raise RulePackError(f"no pack manifest found at '{path}'")


def _rules_path(directory: Path, document: dict[str, Any]) -> Path:
    raw = str(document.get("rules") or document.get("rules_file") or "rules.yaml")
    rules_file = (directory / raw).resolve()
    try:
        rules_file.relative_to(directory.resolve())
    except ValueError as exc:
        raise RulePackError("pack rules file must stay inside the pack") from exc
    if not rules_file.is_file():
        raise RulePackError(f"pack rules file not found: {rules_file}")
    return rules_file


def _signature_path(directory: Path) -> Path:
    return directory / SIGNATURE_FILENAME


def pack_digest(pack: RulePack) -> str:
    return hashlib.sha256(pack.rules_file.read_bytes()).hexdigest()


def _signing_payload(pack: RulePack) -> bytes:
    manifest = {
        "name": pack.name,
        "version": pack.version,
        "description": pack.description,
        "license": pack.license,
        "source": pack.source_url,
        "commit": pack.source_commit,
        "digest": pack.digest or pack_digest(pack),
        "tags": list(pack.tags),
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return canonical + b"\0" + pack.rules_file.read_bytes()


def _resolve_key(key: str | None) -> str:
    secret = key or os.environ.get(SIGNING_KEY_ENV, "")
    if not secret:
        raise RulePackError(
            f"no rule pack signing key; set {SIGNING_KEY_ENV} or pass --key"
        )
    return secret


def load_pack(path: str | Path) -> RulePack:
    manifest = _manifest_path(Path(path))
    document = _read_document(manifest)
    name = str(document.get("name") or "").strip()
    version = str(document.get("version") or "").strip()
    if not name or not version:
        raise RulePackError("pack manifest requires 'name' and 'version'")
    directory = manifest.parent.resolve()
    rules_file = _rules_path(directory, document)
    signature_file = _signature_path(directory)
    signature = str(document.get("signature") or "")
    if signature_file.is_file():
        try:
            signature = signature_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RulePackError(f"could not read pack signature: {exc}") from exc
    digest = str(document.get("digest") or "")
    raw_tags = document.get("tags", [])
    tags = tuple(str(tag) for tag in raw_tags) if isinstance(raw_tags, list) else ()
    return RulePack(
        name=name,
        version=version,
        directory=directory,
        rules_file=rules_file,
        description=str(document.get("description") or ""),
        license=str(document.get("license") or ""),
        source_url=str(document.get("source") or ""),
        source_commit=str(document.get("commit") or ""),
        signature=signature,
        digest=digest,
        tags=tags,
    )


def sign_pack(pack: RulePack, key: str | None = None) -> Path:
    """Writes a sidecar HMAC-SHA256 signature for a pack."""
    secret = _resolve_key(key)
    digest = hmac.new(secret.encode("utf-8"), _signing_payload(pack), hashlib.sha256)
    signature_file = _signature_path(pack.directory)
    signature_file.write_text(
        f"{SIGNATURE_PREFIX}{digest.hexdigest()}\n", encoding="utf-8"
    )
    return signature_file


def verify_pack(
    pack: RulePack,
    key: str | None = None,
    *,
    required: bool = False,
) -> tuple[bool, str]:
    actual_digest = pack_digest(pack)
    if pack.digest and pack.digest.lower() != actual_digest:
        return False, "pack digest does not match the rules file"
    if not pack.signature:
        if required:
            return False, "pack is unsigned"
        return True, "unsigned pack accepted"
    secret = key or os.environ.get(SIGNING_KEY_ENV, "")
    if not secret:
        return False, "pack is signed but no signing key is configured"
    if not pack.signature.startswith(SIGNATURE_PREFIX):
        return False, "unsupported pack signature algorithm"
    expected = pack.signature[len(SIGNATURE_PREFIX) :].strip().lower()
    digest = hmac.new(secret.encode("utf-8"), _signing_payload(pack), hashlib.sha256)
    if not hmac.compare_digest(expected, digest.hexdigest()):
        return False, "pack signature does not match the pack contents"
    return True, "signature verified"


def validate_pack_rules(pack: RulePack) -> tuple[int, tuple[str, ...]]:
    """Returns the number of rules and any non-fatal warnings."""
    try:
        document = yaml.safe_load(pack.rules_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RulePackError(f"could not parse pack rules: {exc}") from exc
    entries = document.get("rules", []) if isinstance(document, dict) else []
    if not isinstance(entries, list) or not entries:
        raise RulePackError("pack rules file must contain a non-empty 'rules' list")
    warnings: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            warnings.append(f"rule entry {index} is not an object and will be skipped")
            continue
        if not entry.get("id"):
            warnings.append(f"rule entry {index} has no 'id'")
        if not (entry.get("regex") or entry.get("pattern")):
            warnings.append(f"rule entry {index} has no 'regex'/'pattern'")
    return len(entries), tuple(warnings)


def discover_packs(directory: str | Path | None = None) -> tuple[RulePack, ...]:
    root = Path(directory).expanduser() if directory else DEFAULT_PACK_DIR
    if not root.is_dir():
        return ()
    packs: list[RulePack] = []
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir():
            continue
        try:
            packs.append(load_pack(candidate))
        except RulePackError:
            continue
    return tuple(packs)


def _is_git_source(source: str) -> bool:
    if source.startswith(("git+", "git@")):
        return True
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https", "ssh"} and (
        source.endswith(".git") or parsed.scheme == "ssh"
    )


def _checkout_source(source: str, workdir: Path) -> Path:
    if not _is_git_source(source):
        return Path(source).expanduser().resolve()
    url = source.removeprefix("git+")
    destination = workdir / "source"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--", url, str(destination)],
            check=True,
            capture_output=True,
            timeout=_GIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RulePackError(f"could not clone rule pack '{source}': {exc}") from exc
    return destination


def _copy_pack(source: Path, destination: Path, force: bool) -> None:
    if destination.exists():
        if not force:
            raise RulePackError(
                f"rule pack already exists at '{destination}'; pass --force"
            )
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def install_pack(
    source: str | Path,
    *,
    directory: str | Path | None = None,
    force: bool = False,
    allow_unsigned: bool = False,
    key: str | None = None,
) -> RulePack:
    """Installs and verifies a local or git-hosted rule pack."""
    root = Path(directory).expanduser() if directory else DEFAULT_PACK_DIR
    with tempfile.TemporaryDirectory(prefix="commit-guard-pack-") as temporary:
        checked_out = _checkout_source(str(source), Path(temporary))
        pack = load_pack(checked_out)
        verified, reason = verify_pack(
            pack, key, required=not allow_unsigned  # commit-guard-ignore
        )
        if not verified:
            raise RulePackError(f"refusing to install '{pack.name}': {reason}")
        count, warnings = validate_pack_rules(pack)
        if warnings:
            raise RulePackError(
                f"refusing to install '{pack.name}': " + "; ".join(warnings)
            )
        root.mkdir(parents=True, exist_ok=True)
        destination = root / pack.name
        _copy_pack(pack.directory, destination, force)
        installed = load_pack(destination)
        if count <= 0:  # pragma: no cover - validate_pack_rules already checks
            raise RulePackError("installed pack contains no rules")
        return installed


def remove_pack(name: str, directory: str | Path | None = None) -> RulePack:
    root = Path(directory).expanduser() if directory else DEFAULT_PACK_DIR
    target = root / name
    pack = load_pack(target)
    shutil.rmtree(target)
    return pack


def load_registry(source: str | Path) -> RulePackRegistry:
    raw = str(source)
    with tempfile.TemporaryDirectory(prefix="commit-guard-registry-") as temporary:
        if _is_git_source(raw):
            checkout = _checkout_source(raw, Path(temporary))
            registry_path = checkout / REGISTRY_FILENAME
        else:
            candidate = Path(raw).expanduser()
            registry_path = (
                candidate / REGISTRY_FILENAME if candidate.is_dir() else candidate
            )
        if not registry_path.is_file():
            raise RulePackError(f"registry not found: {registry_path}")
        document = _read_document(registry_path)
    entries_raw = document.get("packs", [])
    if not isinstance(entries_raw, list):
        raise RulePackError("registry 'packs' must be a list")
    entries: list[RegistryEntry] = []
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        pack_source = str(item.get("source") or "").strip()
        if not name or not version or not pack_source:
            continue
        entries.append(
            RegistryEntry(
                name=name,
                version=version,
                source=pack_source,
                path=str(item.get("path") or ""),
                digest=str(item.get("digest") or ""),
                signature=str(item.get("signature") or ""),
                description=str(item.get("description") or ""),
            )
        )
    return RulePackRegistry(source=raw, entries=tuple(entries))


def install_from_registry(
    registry_source: str | Path,
    name: str,
    *,
    directory: str | Path | None = None,
    force: bool = False,
    allow_unsigned: bool = False,
    key: str | None = None,
) -> RulePack:
    registry = load_registry(registry_source)
    entry = registry.find(name)
    source = entry.source
    if not _is_git_source(source):
        candidate = Path(source).expanduser()
        if not candidate.is_absolute():
            base = Path(str(registry_source)).expanduser()
            if base.is_file():
                base = base.parent
            candidate = base / candidate
        source = str(candidate)
    pack = install_pack(
        source,
        directory=directory,
        force=force,
        allow_unsigned=allow_unsigned,
        key=key,
    )
    if entry.digest and entry.digest.lower() != pack_digest(pack):
        remove_pack(pack.name, directory)
        raise RulePackError(
            f"registry digest for '{name}' does not match the installed pack"
        )
    return pack
