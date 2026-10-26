# SPDX-License-Identifier: Apache-2.0
"""Validates the rule provenance manifest against the files on disk."""

from __future__ import annotations

import hashlib
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "rules" / "PROVENANCE.yaml"
RULE_SUFFIXES = {".conf", ".py", ".toml", ".yaml", ".yml"}
IGNORED_NAMES = {"__init__.py", "PROVENANCE.yaml"}
REQUIRED_SOURCE_FIELDS = {
    "id",
    "kind",
    "status",
    "project",
    "source_url",
    "revision",
    "retrieved",
    "license",
    "license_url",
    "redistribution",
    "files",
}
REQUIRED_FILE_FIELDS = {"path", "sha256"}


def _load_manifest() -> dict:
    with PROVENANCE.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _rule_files() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "rules").rglob("*")
        if path.is_file()
        and path.suffix.lower() in RULE_SUFFIXES
        and path.name not in IGNORED_NAMES
    }


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = _load_manifest()
        self.sources = self.manifest["sources"]

    def test_every_rule_file_has_exactly_one_entry(self) -> None:
        recorded = [
            item["path"]
            for source in self.sources
            for item in source["files"]
        ]
        self.assertEqual(len(recorded), len(set(recorded)))
        self.assertEqual(set(recorded), _rule_files())

    def test_source_fields_and_status_semantics(self) -> None:
        for source in self.sources:
            missing = REQUIRED_SOURCE_FIELDS - source.keys()
            self.assertFalse(missing, f"{source.get('id')} missing {missing}")
            if source["status"] == "release-blocked":
                self.assertEqual(source["redistribution"], "blocked")
                self.assertFalse(source["packaged"], source["id"])

    def test_checksums_match(self) -> None:
        for source in self.sources:
            for item in source["files"]:
                missing = REQUIRED_FILE_FIELDS - item.keys()
                self.assertFalse(missing, f"{item.get('path')} missing {missing}")
                digest = hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest()
                self.assertEqual(digest, item["sha256"], item["path"])

    def test_release_blocked_packs_are_excluded_from_package_data(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)
        excluded = set(
            project["tool"]["setuptools"]["exclude-package-data"].get("rules", [])
        )
        for source in self.sources:
            if source["status"] == "release-blocked":
                for item in source["files"]:
                    relative = Path(item["path"]).relative_to("rules").as_posix()
                    self.assertTrue(
                        any(_matches(relative, pattern) for pattern in excluded),
                        f"{relative} is not covered by exclude-package-data",
                    )


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**/*"):
        return path.startswith(pattern[: -len("/**/*")] + "/")
    if pattern.endswith("/*"):
        return path.startswith(pattern[: -len("/*")] + "/")
    return path == pattern


if __name__ == "__main__":
    unittest.main()
