# SBOM, Licenses, Editor Loops, Compliance, and Plugins

These surfaces share one rule: they are local-first, read untrusted repository
content defensively, and never turn a mapping or a score into a certification
claim.

## SBOM and license policy

```bash
commit-guard sbom . --format cyclonedx --output sbom.cdx.json
commit-guard sbom . --format spdx --output sbom.spdx.json
commit-guard license . --policy license-policy.toml --format json
```

`sbom` reads the lockfiles and manifests supported by SCA and emits CycloneDX
1.6 or SPDX 2.3. Components carry a purl, ecosystem, source manifest, version,
and locally available license metadata. A missing license is `NOASSERTION`, not
a guessed permissive license.

`license` is a separate gate from the security threshold. The default policy
allows common permissive licenses, denies strong copyleft and source-available
licenses, and sends weak copyleft to review. Unknown, review, and denied
dependencies are counted separately.

```toml
fail_on_unknown = false
fail_on_review = false
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]
deny = ["AGPL-3.0-only", "SSPL-1.0"]
review = ["MPL-2.0", "EPL-2.0"]
```

Use `--strict` to fail on review and unknown entries. The license report never
changes the security report or its exit status silently.

## Dashboard

```bash
commit-guard dashboard . --reports commit_guard_reports --output dashboard.html
commit-guard dashboard . --format json --history commit_guard_reports/history.json
```

The HTML dashboard is self-contained: no scripts, fonts, or styles are fetched
from the network. It summarizes severity, category, report provenance, owner
grouping, and trend history. Treat generated dashboards as CI artifacts or
local evidence, not as hosted storage.

## Watch and LSP

```bash
commit-guard watch .                 # incremental loop, staged/diff scope
commit-guard watch . --once --all    # one whole-tree audit
commit-guard lsp .
```

Watch mode polls snapshots, debounces bursts of saves, and reports changed,
added, and removed files. `--once` makes it suitable for scripts and CI smoke
tests.

The LSP uses newline-delimited JSON-RPC over stdio. It supports `initialize`,
document open/change/save/close, `publishDiagnostics`, `codeAction`,
`workspace/executeCommand`, `shutdown`, and `exit`. A project does not need
CommitGuard initialized first; the server falls back to bundled rules and the
current document.

## Compliance mapping

```bash
commit-guard compliance . --report report.json --pack owasp-top10-2021 --format markdown
```

Bundled packs map findings by CWE, rule ID, tag, or category:

- OWASP Top 10 2021
- CWE Top 25
- OWASP ASVS 5.0
- PCI DSS 4.0
- SOC 2 Trust Services Criteria (technical evidence subset)

Every report includes the caveat that mapping is not certification. Controls
that require organizational evidence are marked as such; CommitGuard only
shows which findings provide technical evidence.

## Plugins

```bash
commit-guard plugin list
commit-guard plugin validate --dir plugins/example
commit-guard plugin run --dir plugins/example --format json
```

A plugin is a directory containing `plugin.json` and an entrypoint:

```json
{
  "name": "example",
  "version": "1.0.0",
  "entrypoint": "plugin.py",
  "capabilities": ["sast"],
  "signature": "<sha256-of-entrypoint>"
}
```

Plugins are not imported into the CommitGuard process. The runner starts a
separate Python process, sends a JSON request on stdin, caps stdout and runtime,
validates the returned findings against the schema, and rejects categories
outside the manifest capabilities. A missing or mismatched signature is an
error unless the caller passes `--allow-unsigned-plugin` for a deliberately
local plugin.

Plugins are experimental until sandboxing and distribution review are complete.
Do not auto-load plugins from a scanned repository.
