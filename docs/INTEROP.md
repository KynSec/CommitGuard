# Report interoperability

Commit Guard emits JSON schema 3, SARIF 2.1.0, Markdown, JUnit, GitLab Code
Quality, Checkstyle, and HTML.

## Ingesting external tools

```bash
./commit-guard ingest report.sarif --tool auto --output external.json
./commit-guard ingest semgrep.json --tool semgrep --output semgrep.json
./commit-guard ingest gitleaks.json --tool gitleaks --output gitleaks.json
./commit-guard report merge --output merged.json scan.json external.json
```

Supported native formats are Semgrep JSON, gitleaks JSON, Trivy JSON, Checkov
JSON, and Bandit JSON. SARIF 2.x is supported with `--tool auto` or
`--tool sarif`. Input is capped at 50 MB and relative paths are confined to the
repository unless `--allow-outside` is supplied.

## Normalization

Findings receive a stable fingerprint, engine name, category, confidence, and
optional CWE, fix, references, and code-flow data. Secret findings are masked
in output unless explicitly requested. Tool severity is mapped to
`critical`, `high`, `medium`, `low`, or `info`, with the original value kept
under provenance.

## Merging

`report merge` loads Commit Guard JSON, SARIF, and the native formats above,
deduplicates equivalent findings, and writes a merged Commit Guard JSON report.
Source files are hashed in the merged output for auditability. Reports from
different tools may disagree on severity; the conservative (higher) value is
retained.

## Other tools

Tools without a native adapter can still participate through SARIF. For
example, Ruff's `--output-format sarif` output is accepted by `--tool auto`
or `--tool sarif`.
