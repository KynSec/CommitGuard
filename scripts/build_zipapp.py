#!/usr/bin/env python3
"""Builds the single-file CommitGuard zipapp.

The archive contains the scan engine, the read-only command surfaces, the
bundled native rules, and the Markdown documentation package.  Semgrep packs
stay out because their upstream license forbids redistribution.  Rules are
extracted to the user cache when the archive changes so the scan engine can
keep using normal filesystem paths.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = (
    "main.py",
    "install_hook.py",
    "gui_server.py",
    "gui_actions.py",
    "gui_page.py",
)
INCLUDE_DIRS = ("core", "rules")
DOCS_DIR = "docs"
DOCS_PACKAGE = "commit_guard_docs"
EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EXCLUDE_RULE_DIRS = {"semgrep_rules"}

BOOTSTRAP = '''"""CommitGuard zipapp bootstrap."""

import os
import sys
import tempfile
import zipfile
from pathlib import Path


def _extract_rules() -> Path | None:
    archive = Path(sys.argv[0]).resolve()
    if not zipfile.is_zipfile(archive):
        return None
    cache_root = Path(
        os.environ.get("COMMITGUARD_CACHE_DIR")
        or Path.home() / ".cache" / "commitguard"
    )
    target = cache_root / "rules"
    stat = archive.stat()
    stamp = f"{stat.st_size}:{stat.st_mtime_ns}"
    marker = cache_root / ".complete"
    if marker.is_file():
        try:
            if marker.read_text(encoding="utf-8").strip() == stamp:
                return target
        except OSError:
            pass
    try:
        cache_root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if name == "rules" or name.startswith("rules/"):
                    bundle.extract(name, cache_root)
        marker.write_text(stamp + "\\n", encoding="utf-8")
        return target
    except OSError:
        fallback = Path(tempfile.mkdtemp(prefix="commitguard-rules-"))
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if name == "rules" or name.startswith("rules/"):
                    bundle.extract(name, fallback)
        return fallback / "rules"


_rules = _extract_rules()
if _rules is not None:
    os.environ["COMMITGUARD_RULES_DIR"] = str(_rules)

COMMANDS = {
    "sbom",
    "license",
    "dashboard",
    "watch",
    "lsp",
    "compliance",
    "plugin",
    "scan",
    "check-rules",
    "explain",
    "suppressions",
    "gate",
    "ingest",
    "report",
    "policy",
    "triage",
    "baseline",
    "rules",
    "doctor",
    "status",
    "init",
}

if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
    import install_hook

    raise SystemExit(install_hook.main())
else:
    import main

    raise SystemExit(main.main())
'''


def _ignore(directory: str, names: list[str]) -> set[str]:
    ignored = {name for name in names if name in EXCLUDE_NAMES}
    if Path(directory).name == "rules":
        ignored.update(name for name in names if name in EXCLUDE_RULE_DIRS)
    if Path(directory).name == DOCS_DIR:
        ignored.add("site")
    return ignored


def build(output: Path) -> Path:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="commitguard-zipapp-") as directory:
        staging = Path(directory)
        for name in INCLUDE:
            source = ROOT / name
            if not source.is_file():
                raise SystemExit(f"missing required file: {source}")
            shutil.copy2(source, staging / name)
        for name in INCLUDE_DIRS:
            source = ROOT / name
            if not source.is_dir():
                raise SystemExit(f"missing required directory: {source}")
            shutil.copytree(source, staging / name, ignore=_ignore)
        docs_source = ROOT / DOCS_DIR
        if not docs_source.is_dir():
            raise SystemExit(f"missing required directory: {docs_source}")
        shutil.copytree(docs_source, staging / DOCS_PACKAGE, ignore=_ignore)
        (staging / "__main__.py").write_text(BOOTSTRAP, encoding="utf-8")
        zipapp.create_archive(
            staging,
            target=output,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "commit-guard.pyz",
    )
    args = parser.parse_args(argv)
    output = build(args.output)
    size = output.stat().st_size
    print(f"Built {output} ({size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
