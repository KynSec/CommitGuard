<div align="center">

# CommitGuard

**The local security control plane that runs before your commit.**

Secrets, risky code, dependencies, and imported analyzer findings. One policy,
one baseline, one fast gate. No telemetry. No source upload. No waiting for CI.

[![CI](https://github.com/CommitGuard-Sec/CommitGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitGuard-Sec/CommitGuard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Offline first](https://img.shields.io/badge/offline-first-2ea043)](#privacy-model)
[![Zero telemetry](https://img.shields.io/badge/telemetry-zero-success)](#privacy-model)
[![Release](https://img.shields.io/badge/release-3.0%20preview-orange)](#release-status)

[Quickstart](#quickstart-in-60-seconds) · [Why CommitGuard](#why-commitguard) · [Features](#feature-matrix) · [CLI](#cli-at-a-glance) · [Architecture](#architecture) · [Docs](#documentation)

</div>

---

```text
$ commit-guard scan --staged

  COMMITGUARD  policies: balanced  rules: 418  mode: staged diff
  ------------------------------------------------------------
  CRITICAL  0    HIGH  1    MEDIUM  1    LOW  0    INFO  0
  ------------------------------------------------------------
  src/payments/client.py:42   cg-python-weak-random-secret   HIGH
  src/settings.py:17          cg-python-django-wildcard-hosts MEDIUM

  STATUS: FAILED  (>= high severity)
  Scanned 214 line(s) in 0.42s
```

## Why CommitGuard

Most security tools tell you what was wrong **after** the code left your machine.
CommitGuard moves the control point to the developer's local loop.

- **Sub-second feedback.** Warm staged scans complete under one second on the
  reference diff. Fix the issue while the context is still fresh.
- **Offline by default.** Normal scans make no network calls, collect no
  telemetry, and never upload source code. Optional online features are explicit.
- **One decision engine.** Regex, secrets, Python AST taint, SCA, and imported
  SARIF findings all flow through the same baseline, triage, and policy gate.
- **Built for real repositories.** Stable fingerprints, new-code ratchets,
  owner/expiry metadata, path allowlists, and committed triage decisions.
- **CI parity.** The same rules and exit codes run in a pre-commit hook, locally,
  in GitHub Actions, or from a raw SARIF report.
- **A local console, not a cloud dashboard.** The loopback GUI handles triage,
  fixes, policies, pipelines, Git operations, and rule inspection on your machine.

## Quickstart in 60 Seconds

```bash
# Install with pipx. Use the official GitHub source until the first PyPI release.
pipx install "git+https://github.com/CommitGuard-Sec/CommitGuard.git"

# Or, once published:
# pipx install commit-guard

# Initialize in any Git repository
cd /path/to/your/repo
commit-guard init

# Stage your work and run the local gate
git add .
commit-guard scan --staged
```

That is the whole loop: install, initialize, scan. No account, API key, cloud
project, or network connection is needed for a normal scan.

To make the gate run automatically before every commit:

```bash
commit-guard install .
```

The installer keeps a self-contained copy in `.commit_guard/`, writes the
hook, and preserves your existing configuration and ignore files.

### Release status

CommitGuard is on the **3.0 preview** line while the package version remains
`2.1.0`. GitHub source installs work today; the first PyPI publication is
pending. Pin a release tag or commit SHA for production use.

## Install Options

| Method | Command | Best for |
|---|---|---|
| pipx | `pipx install "git+https://github.com/CommitGuard-Sec/CommitGuard.git"` | Isolated CLI install today |
| PyPI | `pipx install commit-guard` | After the first release |
| pip | `python -m pip install "git+https://github.com/CommitGuard-Sec/CommitGuard.git"` | Existing virtual environments |
| Source | `git clone https://github.com/CommitGuard-Sec/CommitGuard.git` | Development and review |
| pre-commit | `commit-guard install . --no-hook` | Framework-managed hooks |
| GitHub Action | `uses: CommitGuard-Sec/CommitGuard@<tag-or-sha>` | CI enforcement |

Requirements: **Python 3.11+**, **git**, and **PyYAML 6+** (installed
automatically). Linux, macOS, Windows, Git worktrees, and custom
`core.hooksPath` are supported.

## Feature Matrix

| Capability | What CommitGuard gives you | Offline |
|---|---|---|
| Staged commit gate | Scans only added lines with stable exit codes and a policy decision. | Yes |
| Secret detection | 220+ gitleaks-style rules with entropy, keywords, path filters, and allowlists. Values are redacted by default. | Yes |
| SAST | 120+ curated native rules for Python, JS/TS, Go, Java, PHP, Ruby, Rust, C/C++, shell, frameworks, CI, Kubernetes, Terraform, and Docker. | Yes |
| Python taint | Standard-library AST checks for common request/input flows into SQL and shell sinks. | Yes |
| Dependencies | Pinned-dependency checks against an offline OSV snapshot, with opt-in OSV.dev lookup. | Yes / opt-in |
| Analyzer interop | Normalize and merge SARIF or native output from Semgrep, CodeQL, Trivy, Checkov, Bandit, and gitleaks. | Yes |
| Policy engine | `strict`, `balanced`, and `audit` profiles; thresholds, budgets, ratchets, and new-code gating. | Yes |
| Baseline and triage | Fingerprints, accepted-risk metadata, owners, expiry, stale-entry audits, and committed triage YAML. | Yes |
| Fix workflow | Preview and apply rule-provided fixes, then re-stage safely. | Yes |
| Reports | Markdown, JSON schema 3, SARIF 2.1.0, self-contained HTML, JUnit, GitLab Code Quality, and Checkstyle. | Yes |
| Local GUI | Loopback-only console for scans, policy, triage, fixes, pipelines, Git, rules, reports, and configuration. | Yes |
| CI and hooks | Composite GitHub Action, native pre-commit/pre-push hooks, and pre-commit framework support. | Yes |
| Rule QA | Schema validation, regex compilation, positive/negative corpus tests, and rule inspection. | Yes |
| Privacy | Zero telemetry, no source upload, local reports, and redaction across every output format. | Yes |

## CLI at a Glance

```bash
# Gate the staged diff
commit-guard scan --staged
commit-guard scan --staged --threshold medium
commit-guard scan --staged --fix-dry-run
commit-guard scan --staged --gate --policy-profile balanced

# Scan a branch, history, or the whole tree
commit-guard scan --diff origin/main...HEAD
commit-guard scan --history 50
commit-guard scan --all

# Dependencies and reports
commit-guard scan --sca
commit-guard scan --sca --sca-online        # explicit network opt-in
commit-guard scan --format sarif
commit-guard scan --format html

# Policy, baseline, and triage
commit-guard gate --staged
commit-guard baseline update --owner security --expiry 2026-12-31
commit-guard triage list
commit-guard triage audit

# Bring findings from other analyzers into the same gate
commit-guard ingest semgrep.sarif trivy.json checkov.sarif
commit-guard report merge reports/*.sarif --format sarif --output merged.sarif

# Local console and maintenance
commit-guard gui
commit-guard status
commit-guard doctor
commit-guard rules check
```

Exit codes are intentionally simple:

| Code | Meaning |
|---|---|
| `0` | Clean, or every finding is below the blocking policy. |
| `1` | Blocking findings or a policy failure. Treat this as a failed gate. |
| `2` | CommitGuard could not run: bad repo, config, rules, or dependency. |

## One Policy for Every Analyzer

CommitGuard does not care whether a finding came from its own regex engine, a
Python taint pass, an offline dependency snapshot, or a Semgrep report. Every
finding is normalized into the same schema, fingerprinted, checked against the
baseline and triage state, and evaluated by one local policy.

```toml
[gate]
enabled = true
profile = "balanced"       # strict | balanced | audit
threshold = "high"
fail_on = "new"
ratchet = true
max_new = { critical = 0, high = 0, medium = 25, low = 100 }
```

The result is one reviewable decision instead of five dashboards:

```bash
commit-guard scan --staged --gate
commit-guard gate --report merged.sarif --format json
commit-guard policy validate
commit-guard policy explain cg-python-eval
```

## Architecture

```text
+----------------------- developer machine ------------------------+
|                                                                  |
|   git index                                                      |
|       |                                                          |
|       v                                                          |
|   staged diff ---> secret / regex rules ---+                     |
|       |            Python AST taint --------+                     |
|       |            SCA + OSV snapshot ------+                     |
|       |            SARIF / native reports --+                     |
|       |                                     |                    |
|       +------------------+------------------+                    |
|                          v                                       |
|                 normalized findings                              |
|                 (schema v3, fingerprints)                        |
|                          |                                       |
|               baseline + triage + policy                         |
|                          |                                       |
|                 PASS / FAIL + reports                            |
|                          |                                       |
|              terminal + loopback GUI + CI artifacts              |
|                                                                  |
+------------------------------------------------------------------+
        no telemetry  |  no cloud dependency  |  no source upload
```

Core modules:

- `core/rule_loader.py` loads and caches gitleaks, native, Semgrep-compatible,
  and nuclei-style rules.
- `core/scanner.py` applies path, context, entropy, allowlist, suppression, and
  redaction rules.
- `core/engines/` provides the isolated regex and AST engine adapters.
- `core/policy.py` and `core/triage.py` turn findings into a deterministic gate.
- `core/reporter.py` writes every output format, including SARIF 2.1.0.
- `gui_server.py` serves the token-protected loopback control center.

See [Architecture](docs/ARCHITECTURE.md) for the full data flow and design
tradeoffs.

## Local GUI Console

```bash
commit-guard gui
# opens http://127.0.0.1:8765/?t=<one-time-token>

commit-guard gui --no-open
commit-guard gui --port 0
commit-guard gui --report-only --report-path out/report.html
```

The console includes overview, scan controls, policy gate, triage, pipelines,
fix preview/apply, report PRs, baseline management, Git operations, rule
inspection, reports, maintenance, and a validated config editor.

Security defaults: binds to `127.0.0.1`, requires a per-run token, validates the
`Host` header, caps request bodies, keeps secrets redacted, and runs pipelines
without a shell inside the repository. Hooks and CI never start the GUI.

## Privacy Model

- **No telemetry.** CommitGuard does not phone home, collect usage data, or use
  an LLM service.
- **No source upload.** A normal scan reads the local index, working tree, or
  selected reports and writes local output.
- **Explicit network surfaces.** `--sca-online`, GitHub report/PR actions, and
  rule-pack downloads are opt-in and require your action.
- **Redaction everywhere.** Secrets are masked in terminal output, Markdown,
  JSON, SARIF, HTML, annotations, and the GUI unless you explicitly opt out.
- **Local artifacts.** Reports and the GUI stay on your machine; CI uploads are
  controlled by your workflow.

Read the [Threat Model](docs/THREAT_MODEL.md) and [Security Policy](SECURITY.md)
for the full trust boundaries.

## CI in One Step

```yaml
name: CommitGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # only needed for SARIF upload

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: CommitGuard-Sec/CommitGuard@main
        with:
          format: sarif
          scan-mode: all
          gate: true
          policy-profile: balanced
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: commit_guard_reports/report.sarif
```

Pin the Action to a reviewed tag or commit SHA for production. See
[CI integrations](docs/CI.md) for GitLab, Jenkins, pre-commit, SARIF, and
report-artifact examples.

## Performance

The reference benchmark runs **120 files x 20 added lines** with a warm rule
cache and a median of **~0.96 s** on the development machine used for this
release. First scans after a rule-pack change parse and cache the rules, so they
take longer. The cache invalidates automatically when rule files change.

```bash
commit-guard scan --staged
commit-guard scan --staged --no-cache   # debugging or read-only environments
```

## Known Boundaries

- Native detection is intentionally high-signal and reviewable; it is not a
  claim of complete semantic coverage.
- Python taint is intraprocedural. It does not follow values across modules or
  model every sanitizer.
- Most Semgrep rules require AST support. CommitGuard executes regex-compatible
  rules and records AST-only rules as skipped rather than approximating them.
- Offline SCA depends on the quality and freshness of your local OSV snapshot.
- A leaked credential must be rotated. Suppression and redaction do not undo
  exposure.

## Documentation

| Guide | Start here for |
|---|---|
| [Configuration](docs/CONFIGURATION.md) | Every setting, default, profile, and precedence rule. |
| [Policy](docs/POLICY.md) | Gates, budgets, ratchets, triage, and exit codes. |
| [Rules](docs/RULES.md) | Native schema, rule packs, context windows, and validation. |
| [Interoperability](docs/INTEROP.md) | SARIF/native ingestion and report merging. |
| [CI](docs/CI.md) | GitHub Actions, GitLab, Jenkins, and pre-commit. |
| [Architecture](docs/ARCHITECTURE.md) | Scan flow, modules, caching, and tradeoffs. |
| [Threat Model](docs/THREAT_MODEL.md) | Assets, adversaries, controls, and abuse cases. |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Hooks, paths, caches, and false positives. |
| [Upgrade Guide](docs/UPGRADE-2.x-to-3.x.md) | Schema 2 / 2.x to schema 3 / 3.x. |
| [Contributing](CONTRIBUTING.md) | Development setup, tests, DCO, and rule contributions. |
| [Changelog](CHANGELOG.md) | Release history and notable changes. |

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## Author & Lead Maintainer

> **CommitGuard is created, designed, and led by Amr Khaled Ahmed.**

| | |
|---|---|
| **Lead Author & Creator** | **Amr Khaled Ahmed (Amr Eldhshan)** |
| **GitHub Profile** | [@AmrEldhshan](https://github.com/AmrEldhshan) |
| **Email** | [amr171516@gmail.com](mailto:amr171516@gmail.com) |
| **Official Organization** | [CommitGuard Security (@CommitGuard-Sec)](https://github.com/CommitGuard-Sec) |
| **Official Repository** | [github.com/CommitGuard-Sec/CommitGuard](https://github.com/CommitGuard-Sec/CommitGuard) |

For security reports, follow [SECURITY.md](SECURITY.md). For bugs and feature
requests, use the [official issue tracker](https://github.com/CommitGuard-Sec/CommitGuard/issues).
