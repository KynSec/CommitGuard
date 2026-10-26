# Ingest fixtures

These fixtures are minimal, hand-recorded shapes from pinned tool generations.
They contain no real secrets or live endpoints.

| Tool | Fixture | Format | Recorded against |
|---|---|---|---|
| Semgrep | `semgrep.sarif` | SARIF 2.1.0 | Semgrep 1.90.x output shape |
| Semgrep | `semgrep.json` | native JSON | Semgrep 1.90.x output shape |
| gitleaks | `gitleaks.json` | native JSON | gitleaks 8.x output shape |
| Trivy | `trivy.json` | native JSON | Trivy 0.5x output shape |
| Checkov | `checkov.json` | native JSON | Checkov 3.x output shape |
| Bandit | `bandit.json` | native JSON | Bandit 1.7.x output shape |

Fixtures are test inputs only. They do not imply endorsement or redistribution
rights beyond the repository's own license; regenerate rather than shipping
tool output from a real repository.
