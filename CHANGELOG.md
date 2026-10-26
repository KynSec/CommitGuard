# Changelog

## Unreleased

### Added

- Commit Guard 3.0 preview: JSON schema v3 with stable IDs, engine/category/
  confidence metadata, spans, fixes, references, code flows, and provenance.
- Engine protocol, timeout-isolated parallel runner, deterministic dedupe, and
  built-in `regex` and `ast` engine adapters.
- Policy v1 with `strict`, `balanced`, and `audit` profiles, severity/rate
  budgets, new-code gating, baseline ratchet, and expired-triage handling.
- Committed triage state in `.commit_guard/triage.yaml`.
- SARIF/native ingestion for Semgrep, gitleaks, Trivy, Checkov, and Bandit,
  plus multi-report merging.
- CLI commands: `gate`, `ingest`, `report merge`, `policy validate|explain`,
  and `triage list|set|prune|audit`.
- `scan --gate` and policy-aware pre-commit/pre-push hooks.
- Staged-diff benchmark and CI performance regression job.
- GUI policy-gate and triage actions.
- Apache-2.0 licensing package: SPDX license metadata, `NOTICE`, and
  `THIRD_PARTY_NOTICES.md`.
- Expanded native rule packs to 120+ curated checks across Python,
  JavaScript/TypeScript, Go, Java, PHP, Ruby, Rust, C/C++, shell, web-server
  configuration, GitHub Actions, Kubernetes, Terraform, and Docker.
- `rules/PROVENANCE.yaml` with source, revision, license, retrieval date, and
  SHA-256 checksums for every bundled rule file. Semgrep packs are marked
  release-blocked and excluded from release artifacts.
- `SECURITY.md`, `docs/THREAT_MODEL.md`, and RFC 9116 `security.txt` files with
  private disclosure instructions and a 90-day coordinated disclosure target.
- CI matrix for Python 3.11, 3.12, and 3.13 with lint, type checks, tests, rule
  corpus validation, package build, and release-artifact checks.
- `docs/NAMING.md` with the PyPI availability record and canonical surface
  names, plus `docs/BASELINE.md` with the measured 2.1.0 baseline.
- Optional local web control center (`./commit-guard gui`, `commit-guard-gui`):
  scan modes, severity filters, safe-fix preview/apply with per-finding
  selection, baseline management, rule explorer, configuration editor,
  maintenance actions, report downloads, report pull requests, and inline PR
  suggestions.
- GUI server binds to loopback, requires a per-run token, validates the `Host`
  header, caps request bodies, and keeps secrets redacted by default.
- GUI Git workspace: status/diffs, stage/unstage, commit, fetch/pull/push,
  branch create/switch/delete, stash, remotes, quick-command access to tags and
  advanced operations, recent log, and a recent-history doctor.
- GUI control-plane expansion: repository overview, policy gate with blocking
  reasons, committed triage editor/auditor, and a shell-free delivery pipeline
  console for configured or auto-detected test, lint, type-check, build,
  security, and deploy commands.
- GUI dependency graph preview/save and advanced scan controls for strict,
  soft-fail, GitHub annotations, verbose rules, custom config/rules/baseline,
  no-config, fix preview/apply, and SCA snapshot/timeout.
- Opt-in rule-pack downloads in the GUI: gitleaks TOML, Semgrep-compatible
  YAML, and native YAML. Downloads are validated, size/timeout capped, backed
  up before replacement, and rolled back when they add no usable regex rules.
- `gui`, `gui --report-only`, and `scan --format html` in the installed
  manager; the installer copies the GUI modules into `.commit_guard/`.
- GitHub Action accepts `format: html` and exposes an `html-report` output.
- Tests for GUI actions, HTTP routes/security, fix application, and installer
  integration.

### Changed

- JSON reports now use `schema_version: 3`; SARIF remains 2.1.0 with additional
  fix/code-flow properties. See `docs/UPGRADE-2.x-to-3.x.md`.
- GitHub Action gains `gate`, `policy-file`, and `policy-profile` inputs.
- `core.engines` is included in the wheel and installer copy.
- Redesigned the local GUI with a responsive sidebar, page-aware headers,
  light/dark themes, accessible focus states, consistent cards, sticky table
  headers, mobile layouts, and deep-linkable tabs.
- `scan --format html` is now accepted by the installed `./commit-guard scan`
  wrapper (it was already supported by `main.py`).

## 2.1.0

### Added

- Pre-push scanning with `install --pre-push`; audits every commit in each
  pushed ref range and catches secrets added then removed within the range.
- Audit modes: `scan --history N` (including full history with `0`) and
  `scan --all` for the entire tracked/untracked working tree.
- Baseline automation: `scan --update-baseline`, `--baseline-owner`,
  `--baseline-expiry`, and `suppressions audit` for expired, stale,
  unknown-rule, and unmatched-path entries.
- Optional fingerprint metadata (`# owner=... expiry=...`); expired entries
  stop suppressing findings.
- `--soft-fail` and installer profiles (`--profile strict|balanced|audit`).
- `check-rules`: schema validation, regex compilation checks, and a
  positive/negative corpus (`rules/corpus.yaml`); `explain RULE_ID`.
- SARIF `baselineState`, JSON `baseline_state`, and `--fail-on new` to block
  only findings not accepted in the baseline.
- JUnit XML, GitLab Code Quality JSON, and Checkstyle XML reporters.
- Bounded multi-line context rules (`context.before`, `context.after`,
  `context.regex`) with staged/working-tree content and a curated SQLi example.
- Placeholder filtering for obvious example/dummy secrets and entropy
  thresholds capped to the observed character class (hex vs base64).
- `.pre-commit-hooks.yaml` with tested pre-commit and pre-push hook IDs;
  `install --no-hook` avoids conflicts with the pre-commit framework.
- 112-test stdlib `unittest` suite.

### Changed

- Rule cache format version bumped to `7` for context-window metadata and
  stricter custom-rule validation.
- Version bumped to `2.1.0`.
- Documentation expanded for audit modes, profiles, suppression hygiene, rule
  corpus/context, new reporters, and pre-commit framework usage.

### Fixed

- `--diff`/history scans tolerate repositories with no `HEAD` when persistent
  ignore files are unavailable.
- History/pre-push scans no longer let an `ignore-file` directive from one
  historical commit suppress unrelated commits in the range.
- Global path allowlists are now evaluated once per file instead of once per
  rule per line, keeping `--all` and `suppressions audit` practical.
- `update` preserves the enabled/disabled state of managed hooks and, together
  with `uninstall`/`disable`/`enable`, leaves pre-commit framework hooks
  untouched when Commit Guard was installed with `--no-hook`.

## 2.0.0

### Added

- Config file support (`.commit_guard.toml`): threshold, report format/dir/path,
  redaction, inline suppression toggle, max findings, excludes, report
  allowlists, rule/path allowlists, severity overrides, custom rules directory.
- SARIF 2.1.0 reports for GitHub/Azure code scanning.
- GitHub Actions workflow annotations (automatic under `GITHUB_ACTIONS=true`).
- Secret redaction by default across Markdown, JSON, SARIF, CLI, and
  annotations; `--show-secrets` opts out locally.
- Baseline fingerprints (`fingerprint:`), path suppressions (`path:`), and
  explicit rule entries (`rule:`) in `.commit_guard_ignore`.
- Inline `commit-guard-ignore-next-line` and `commit-guard-ignore-file`.
- `--diff REV` for CI revision-range scans.
- `--list-rules`, `--verbose-rules`, `--no-cache`, `--init-config`, `--version`.
- `update`, `doctor`, and `init` lifecycle commands.
- Curated native rule pack (`rules/custom_rules.yaml`) covering common Python,
  JavaScript, shell, Docker, Kubernetes, and secret patterns.
- Valid nuclei connection-string template (the previous file was an HTTP 404
  page).
- Disk cache for parsed rules: warm scans load in milliseconds instead of
  re-parsing ~100k lines of upstream YAML every commit.
- Full gitleaks field support: `secretGroup`, entropy, keywords, path filters,
  tags, and nested/global allowlists.
- Semgrep `pattern-either` extraction when every branch is a regex.
- Robust unified-diff parsing for paths with spaces and context lines.
- `core.hooksPath` and worktree support in the installer.
- Python/PyYAML/interpreter fallbacks in generated hooks and wrappers.
- 96-test stdlib `unittest` suite (unit + git integration).
- Expanded documentation: configuration, rules, CI, architecture, and
  troubleshooting guides.

### Changed

- Rule loading diagnostics are compact; AST-only semgrep rules no longer spam
  every scan. Use `--verbose-rules` for details.
- Rule cache lives in the user cache directory (override with
  `COMMIT_GUARD_CACHE_DIR`).
- Installer copies docs and ignores bytecode/cache files.
- Uninstall preserves user config, baseline, and reports.
- Reinstalling over Commit Guard's own hook no longer clobbers the original
  hook backup.

### Fixed

- Secrets were written verbatim into reports and JSON.
- Inline global regex flags (`foo(?i)bar`) caused valid gitleaks rules to be
  dropped.
- The OWASP CRS request-signature pack produced severe source-code false
  positives; it is now reference-only under `rules/experimental/`.
- `nuclei_generic_key.yaml` was a 404 error page.
- Context lines were not advancing new-file line numbers (latent parser bug).
- `.gitignore` contained `.commit_guard*`, which would ignore
  `.commit_guard.toml` and `.commit_guard_ignore`.

### Removed

- Default loading of `owasp_sqli.conf` (moved to `rules/experimental/`).
- `bandit_exec_rule.py` from `rules/` (moved to `rules/experimental/` as
  reference; equivalent regex rules ship in `custom_rules.yaml`).
