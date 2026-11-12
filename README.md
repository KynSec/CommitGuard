<div align="center">

# CommitGuard

**The local security control plane that runs before your commit.**

Secrets, risky code, dependencies, and imported analyzer findings. One policy,
one baseline, one fast gate. No telemetry. No source upload. No waiting for CI.

[![CI](https://github.com/KynSec/CommitGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/KynSec/CommitGuard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Offline first](https://img.shields.io/badge/offline-first-2ea043)](#privacy-model)
[![Zero telemetry](https://img.shields.io/badge/telemetry-zero-success)](#privacy-model)
[![Release](https://img.shields.io/badge/release-3.4.1-blue)](#release-status)

[Quickstart](#quickstart-in-60-seconds) · [Why CommitGuard](#why-commitguard) · [Features](#feature-matrix) · [CLI](#cli-at-a-glance) · [Architecture](#architecture) · [Docs](#documentation)

</div>

---

```text
$ commit-guard scan --staged

  COMMITGUARD  policies: balanced  rules: 640  mode: staged diff
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
# Install the signed 3.4.1 wheel from GitHub Releases.
pipx install "https://github.com/KynSec/CommitGuard/releases/download/v3.4.1/commit_guard-3.4.1-py3-none-any.whl"

# Or install from source:
# pipx install "git+https://github.com/KynSec/CommitGuard.git"

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

CommitGuard **3.4.1** is the current release. All four planned phases (0–4) are
implemented. GitHub Releases provide signed wheels, sdists, a single-file
zipapp, the VS Code extension, SBOMs, build provenance, and container images.
The remaining Phase 4 organizational evidence is tracked in
[Phase 4 exit](docs/PHASE4-EXIT.md).

| Phase | Status |
|---|---|
| 0 — Hygiene | Complete |
| 1 — MVP | Complete |
| 2 — Credible 3.0 | Complete |
| 3 — Category tool | Complete |
| 4 — Ecosystem | Implemented and released; external evidence pending |
| 5 — Production hardening & adoption | Next |
| 6 — Team and platform scale | Planned |
| 7 — Detection depth & ecosystem maturity | Planned |

## Install Options

| Method | Command | Best for |
|---|---|---|
| pipx | `pipx install "https://github.com/KynSec/CommitGuard/releases/download/v3.4.1/commit_guard-3.4.1-py3-none-any.whl"` | Isolated CLI install from the signed release |
| PyPI | `pipx install commit-guard` | After trusted publishing is enabled |
| pip | `python -m pip install "https://github.com/KynSec/CommitGuard/releases/download/v3.4.1/commit_guard-3.4.1-py3-none-any.whl"` | Existing virtual environments |
| Source | `git clone https://github.com/KynSec/CommitGuard.git` | Development and review |
| VS Code | [Install release VSIX](https://github.com/KynSec/CommitGuard/releases/download/v3.4.1/commitguard-kynsec-1.0.1.vsix) (`code --install-extension commitguard-kynsec-1.0.1.vsix`) | Live diagnostics and the 1.0.1 scan panel |
| pre-commit | `commit-guard install . --no-hook` | Framework-managed hooks |
| GitHub Action | `uses: KynSec/CommitGuard@v3.4.1` | CI enforcement |
| Docker | `docker pull ghcr.io/kynsec/commitguard:v3.4.1` | Isolated or CI runs |
| Homebrew | Formula in `packaging/homebrew/commitguard.rb` | macOS/Linux package management |
| Scoop | Manifest in `packaging/scoop/commitguard.json` | Windows package management |

Requirements: **Python 3.11+**, **git**, and **PyYAML 6+** (installed
automatically). Linux, macOS, Windows, Git worktrees, and custom
`core.hooksPath` are supported.

The GHCR package may require `docker login ghcr.io` until its visibility is set
to public. In-repo Homebrew and Scoop manifests are updated for 3.4.1; upstream
submission is tracked as part of Phase 5.

### VS Code extension

Install the signed `commitguard-kynsec-1.0.1.vsix` from the
[3.4.1 release](https://github.com/KynSec/CommitGuard/releases/download/v3.4.1/commitguard-kynsec-1.0.1.vsix),
or build it from `editors/vscode/`. Marketplace publication is pending.

The extension starts the local language server for live diagnostics and adds an
Activity Bar scan panel. Version 1.0.1 can scan the current file, staged
changes, or the full repository; select any combination of rule databases
(`custom`, `gitleaks`, `nuclei`, `devskim`, `semgrep`,
`semgrep:semgrep_python`, `python_ast`, `javascript_ast`, `java_ast`,
`go_ast`); scan on save; export JSON; browse the last 20 scans in the History
tab; and show finding counts in the status bar. It runs only in trusted
workspaces.

## Feature Matrix

| Capability | What CommitGuard gives you | Offline |
|---|---|---|
| Staged commit gate | Scans only added lines with stable exit codes and a policy decision. | Yes |
| Secret detection | 220+ gitleaks-style rules with entropy, keywords, path filters, and allowlists. Values are redacted by default. | Yes |
| SAST | 280+ curated native and MIT-licensed DevSkim rules for Python, JS/TS, Go, Java, PHP, Ruby, Rust, C/C++, shell, frameworks, web, CI, Kubernetes, Terraform, and Docker. | Yes |
| Python + JS/TS taint | Standard-library AST checks for request/input flows into SQL, shell, code-exec, SSRF, path, and XSS sinks, with cross-file helper summaries for Python. | Yes |
| Interprocedural taint | Cross-file summaries for JavaScript/TypeScript, Java, and Go wrappers, plus Python helper flows. | Yes |
| SCA reachability + VEX | Import evidence for first-party code, OpenVEX/CycloneDX VEX import/export, and non-blocking `not_affected`/`fixed` decisions. | Yes |
| Signed rule packs + registry | HMAC-signed packs, digest-pinned git registry, install/verify/sign/remove, and revocation. | Yes |
| Local-first AI assistant | Deterministic, redacted, token-bounded context packages; remote providers are disabled unless explicitly enabled. | Yes / opt-in |
| AI evaluation + leaderboard | Reproducible AI evaluation and benchmark leaderboard artifacts. | Yes |
| Native binaries | Optional Linux/macOS/Windows builds for environments without Python. | Yes |
| Governance + security response | Maintainer council, release managers, key custodians, CODEOWNERS, and a 48-hour handoff runbook. | Yes |
| VS Code 1.0.1 | Current-file, staged, and repo scans; scan-on-save; history; JSON export; status-bar counts. | Yes |
| Dependencies | Pinned-dependency checks against an offline OSV snapshot with optional HMAC-signed sidecars, plus opt-in OSV.dev lookup. | Yes / opt-in |
| Analyzer interop | Normalize and merge SARIF or native output from Semgrep, CodeQL, Trivy, Grype, Checkov, Bandit, and gitleaks. | Yes |
| SBOM and licenses | CycloneDX 1.6, SPDX 2.3, and an allow/deny/review license policy with separate exit status. | Yes |
| Compliance | Control mapping packs for OWASP Top 10, CWE Top 25, ASVS 5.0, PCI DSS 4.0, and SOC 2 technical evidence, with explicit caveats. | Yes |
| Editor and watch loops | Stdio LSP diagnostics/code actions, a VS Code extension, and `watch --once` incremental snapshots. | Yes |
| Dashboard | Self-contained HTML/JSON with severity, category, owner, trend, and report provenance. | Yes |
| Plugins | Signed manifests, verified install/remove, out-of-process execution, capability limits, timeouts, and output caps. | Yes |
| Policy engine | `strict`, `balanced`, and `audit` profiles; thresholds, budgets, ratchets, and new-code gating. | Yes |
| Baseline and triage | Fingerprints, accepted-risk metadata, owners, expiry, stale-entry audits, and committed triage YAML. | Yes |
| Quarterly audit | Local reports, triage state, bounded history, and optional compliance packs without scanning or network access. | Yes |
| Fix workflow | Preview and apply rule-provided fixes, then re-stage safely. | Yes |
| Reports | Markdown, JSON schema 3, SARIF 2.1.0, self-contained HTML, JUnit, GitLab Code Quality, and Checkstyle. | Yes |
| Local GUI | Loopback-only console for scans, policy, triage, fixes, pipelines, Git, rules, reports, and configuration. | Yes |
| CI and hooks | Composite GitHub Action, GitLab MR summaries/inline suggestions, native pre-commit/pre-push hooks, and pre-commit framework support. | Yes |
| Release artifacts | Wheel, sdist, single-file zipapp, signed checksums, build provenance, SBOM, and a container image. | Yes |
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

# Determinant profiles and explicit file/rule selection
commit-guard scan --list-profiles
commit-guard scan --profile app-code
commit-guard scan --profile python-security --include "src/**" --rule "cg-python-*"
commit-guard scan --profile secrets-only --exclude "tests/fixtures/**"

# Dependencies and reports
commit-guard scan --sca
commit-guard scan --sca --sca-online        # explicit network opt-in
commit-guard scan --format sarif
commit-guard scan --format html
commit-guard sbom . --format cyclonedx --output sbom.json
commit-guard license . --policy license-policy.toml
commit-guard dashboard . --output dashboard.html

# Developer loops
commit-guard watch .                       # incremental re-scan on save
commit-guard watch . --once --all          # one audit scan, then exit
commit-guard lsp .                         # stdio language server

# Ecosystem surfaces
commit-guard scan --sca-reachability
commit-guard compliance . --report report.json --pack owasp-top10-2021
commit-guard vex export --report report.json --output openvex.json
commit-guard vex apply --report report.json --vex openvex.json
commit-guard ai explain --report report.json --fingerprint <fp>
commit-guard ai context --report report.json --output context.json
commit-guard packs install --source ./pack
commit-guard packs verify --dir ~/.config/commitguard/packs
commit-guard packs registry-install --registry registry.json --name <pack>
commit-guard plugin list
commit-guard plugin install --source plugins/example
commit-guard plugin verify --dir plugins

# Policy, baseline, and triage
commit-guard gate --staged
commit-guard baseline update --owner security --expiry 2026-12-31
commit-guard triage list
commit-guard triage audit
commit-guard audit . --reports commit_guard_reports --since 2026-01-01

# Bring findings from other analyzers into the same gate
commit-guard ingest semgrep.sarif trivy.json grype.json checkov.sarif
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
- `core/interprocedural.py` builds cross-file taint summaries for JS/TS, Java, and Go.
- `core/reachability.py` records SCA import evidence; `core/vex.py` applies VEX decisions.
- `core/rule_packs.py` verifies, signs, installs, and resolves signed third-party packs.
- `core/ai_assistant.py` builds redacted, local-first context packages.
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

The console includes overview, scan controls, determinant profile/file/rule
selection, policy gate, triage, pipelines, fix preview/apply, report PRs,
baseline management, Git operations, rule inspection, an in-app profiles
guide, reports, maintenance, and a validated config editor.

Security defaults: binds to `127.0.0.1`, requires a per-run token, validates the
`Host` header, caps request bodies, keeps secrets redacted, and runs pipelines
without a shell inside the repository. Hooks and CI never start the GUI.

## Privacy Model

- **No telemetry.** CommitGuard does not phone home, collect usage data, or call
  an LLM by default.
- **Local-first AI.** `commit-guard ai` builds deterministic, redacted context
  packages locally; remote providers require `--allow-network` and explicit
  configuration.
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
      - uses: KynSec/CommitGuard@v3.4.1
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
cache. CI enforces a **2,000 ms** median ceiling; recorded medians vary by host
and are published in [BASELINE.md](docs/BASELINE.md). First scans after a
rule-pack change parse and cache the rules, so they take longer. The cache
invalidates automatically when rule files change.

```bash
commit-guard scan --staged
commit-guard scan --staged --no-cache   # debugging or read-only environments
```

## Known Boundaries

- Native detection is intentionally high-signal and reviewable; it is not a
  claim of complete semantic coverage.
- Python taint uses conservative cross-file function summaries. Ambiguous
  helpers with the same name can increase false positives, and arbitrary
  abstractions, aliases, and sanitizers are still not fully modelled.
- Interprocedural summaries for JS/TS, Java, and Go are name-based and
  conservative; Java and Go analysis is syntax-driven, not type-resolved.
- Native binaries are convenience artifacts, not the canonical signed release.
- The benchmark leaderboard does not compare against commercial products.
- Local AI context is review material, not a substitute for human triage.
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
| [Rules](docs/RULES.md) | Native schema, rule packs, context windows, selection, and validation. |
| [Scan profiles](docs/SCAN_PROFILES.md) | Determinant file/rule selections in `rules/scan_profiles.yaml`, CLI/GUI usage, and PyPI packaging. |
| [Interoperability](docs/INTEROP.md) | SARIF/native ingestion and report merging. |
| [Ecosystem](docs/ECOSYSTEM.md) | SBOM, licenses, dashboard, watch, LSP, compliance, quarterly audits, plugins, signed rule packs, AI evaluation, native binaries, and the benchmark leaderboard. |
| [Governance](GOVERNANCE.md) | Roles, decision making, maintainer continuity, and release rotation. |
| [Maintainers](MAINTAINERS.md) | Current role assignments and responsibilities. |
| [Security response](docs/SECURITY-RESPONSE.md) | Incident runbook, severity targets, and maintainer-absence handoff. |
| [Phase 4 exit](docs/PHASE4-EXIT.md) | Deliverable and exit-criterion evidence, reproduction commands, and known limits. |
| [CI](docs/CI.md) | GitHub Actions, GitLab, Jenkins, and pre-commit. |
| [GitLab](docs/GITLAB.md) | MR summaries, inline suggestions, and signed offline snapshots. |
| [Benchmarks](docs/BENCHMARKS.md) | Benchmark card, fixed-commit accuracy corpus, and limitations. |
| [Releasing](docs/RELEASING.md) | Signed artifacts, offline verification, zipapp, and container image. |
| [Architecture](docs/ARCHITECTURE.md) | Scan flow, modules, caching, and tradeoffs. |
| [Threat Model](docs/THREAT_MODEL.md) | Assets, adversaries, controls, and abuse cases. |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Hooks, paths, caches, and false positives. |
| [Support](docs/SUPPORT.md) | Support guide, evidence bundle, triage matrix, and escalation. |
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
| **GitHub Profile** | [@Amr-Khaled-Ahmed](https://github.com/Amr-Khaled-Ahmed) |
| **Email** | [amr171516@gmail.com](mailto:amr171516@gmail.com) |
| **Official Organization** | [CommitGuard Security (@KynSec)](https://github.com/KynSec) |
| **Official Repository** | [github.com/KynSec/CommitGuard](https://github.com/KynSec/CommitGuard) |

For security reports, follow [SECURITY.md](SECURITY.md). For bugs and feature
requests, use the [official issue tracker](https://github.com/KynSec/CommitGuard/issues).
