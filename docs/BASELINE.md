# CommitGuard 2.1.0 baseline

Measured on 2026-10-26 from the working tree that includes the recorded GUI
changes. The intended baseline tag is `v2.1.0-baseline`.

| Item | Value |
|---|---|
| Version | 2.1.0 |
| Last commit before baseline packaging | `8ad2b28` (`fix the gui`) |
| Working-tree changes included | `gui_page.py`, `tests/test_gui_page.py`, removal of `AegisPlan.md` |
| Test command | `python -m unittest discover -s tests -v` |
| Tests before Phase 0 | 205 passed, 0 failed |
| Tests after Phase 0 provenance checks | 209 passed, 0 failed |
| Active rules | 342 |
| Skipped rule entries | 2,059 |
| Corpus samples | 25 |
| Schema/corpus issues | 0 |
| Runtime dependency | PyYAML>=6.0 |
| Local Python used for measurement | 3.14.7 |
| CI Python matrix | 3.11, 3.12, 3.13 |

Reproduce the rule numbers with:

```bash
python main.py --list-rules
python main.py --check-rules
python -m unittest discover -s tests -v
```

## Baselines versus the master plan

The master plan records 194 tests and 340 active rules from its 2026-10-24
measurement. The working tree now has 205 tests and 342 active rules because the
GUI work and the current rule set are included. The measured values above are
the authoritative baseline for this checkout.

## Tagging

The baseline tag must point at a commit that contains the recorded GUI work,
not at a dirty tree. Prefer a GUI-only baseline commit before the Phase 0
hygiene files, so the tag identifies the measured 2.1.0 state:

```bash
git add gui_page.py tests/test_gui_page.py
git commit -s -m "chore: record CommitGuard 2.1.0 GUI baseline"
git tag -a v2.1.0-baseline -m "CommitGuard 2.1.0 baseline"
```

Then commit the Phase 0 hygiene changes separately. If the tag is created after
Phase 0 is committed, label it as the Phase 0 exit tag instead of a pure 2.1.0
baseline. Do not move an existing baseline tag.

## Phase 1 preview verification

Measured on 2026-10-26 after the CommitGuard 3.0 preview implementation:

| Item | Value |
|---|---|
| Tests | 273 passed, 0 failed |
| JSON schema | 3 |
| Active rules | 342 |
| Skipped rule entries | 2,059 |
| Default staged benchmark median | ~990 ms (120 files x 20 lines, warm cache) |
| Lint / type check | `ruff` clean; `mypy` clean for 33 application sources |

This is a verification snapshot, not a release tag. The historical 2.1.0
baseline above remains the comparison point for Phase 0.

## Phase 2/3 implementation snapshot

Measured on 2026-10-29 from the working tree that adds the ecosystem surfaces:

| Item | Value |
|---|---|
| Tests | 321 passed, 15 subtests passed |
| JSON schema | 3 |
| Active rules | 640 |
| Skipped rule entries | 2,059 |
| Corpus samples | 151 |
| Schema/corpus issues | 0 |
| Lint / type check | `ruff` clean; `mypy` clean for 43 application sources |
| Local Python used for measurement | 3.14.7 |

Reproduce this snapshot with:

```bash
python -m pytest -q
python main.py --check-rules
ruff check main.py install_hook.py gui_server.py gui_actions.py gui_page.py core tests scripts benchmarks
mypy main.py install_hook.py gui_server.py gui_actions.py gui_page.py core
```

This snapshot covers the Phase 2/3 command surfaces, SBOM/license policy,
dashboard, watch mode, language server, compliance packs, plugins, Grype
ingestion, and JavaScript/TypeScript taint flows. It is not a release tag.

## Phase 2 completion snapshot

Measured on 2026-11-03 after closing the Phase 2 exit items:

| Item | Value |
|---|---|
| Tests | 336 passed, 15 subtests passed |
| JSON schema | 3 |
| Accuracy corpus | 14/14 checks (7 vulnerable + 7 fixed cases) |
| Staged benchmark | ~1.33 s median (120 files x 20 lines) |
| Lint / type check | `ruff` clean; `mypy` clean for 44 application sources |
| Zipapp smoke test | `--version` and `sbom` succeed |

This snapshot adds cross-file Python taint summaries, signed OSV snapshots,
GitLab MR publishing, the VS Code extension with an Activity Bar scan panel,
the zipapp and release workflow, the accuracy gate, upgrade end-to-end tests,
and CI dogfooding.

## Phase 3 completion snapshot

Measured on 2026-11-06 from the `phase-3-completion` branch before commit:

| Item | Value |
|---|---|
| Tests | 370 passed, 18 subtests passed |
| JSON schema | 3 |
| Active rules | 640 |
| Skipped rule entries | 2,059 |
| Corpus samples | 151 |
| Schema/corpus issues | 0 |
| Accuracy corpus | 14/14 checks (7 vulnerable + 7 fixed cases) |
| Staged benchmark on this host | ~2.33 s median (120 files x 20 lines) |
| Parent commit benchmark on this host | ~2.32 s median |
| Lint / type check | `ruff` clean; `mypy` clean for 46 application sources |
| Zipapp smoke test | `--version` and `audit` succeed |
| Local Python used for measurement | 3.14.8 |

The local benchmark host exceeded the 2000 ms CI limit, but the parent commit
measured within 10 ms of this branch, so Phase 3 introduced no measurable scan
regression. The CI latency gate remains 2000 ms.

Phase 3 exit criteria are covered by `tests/test_phase3_exit.py`:

- Five external tool reports (Semgrep, gitleaks, Trivy, Checkov, Grype) and a
  CommitGuard report merge into one gate.
- A plugin can be installed, verified, and removed without affecting core
  commands.
- A quarterly audit can be generated from local reports, triage state, history,
  and compliance packs without scanning.
- The accuracy gate remains 14/14, and the staged benchmark is unchanged
  against the parent commit.

Reproduce this snapshot with:

```bash
python -m pytest -q tests
python main.py --check-rules --repo .
python benchmarks/accuracy_benchmark.py
python benchmarks/scan_benchmark.py --iterations 3 --max-median-ms 2000
ruff check main.py install_hook.py gui_server.py gui_actions.py gui_page.py core tests benchmarks scripts
mypy main.py install_hook.py gui_server.py gui_actions.py gui_page.py core
python scripts/build_zipapp.py --output dist/commit-guard.pyz
```
