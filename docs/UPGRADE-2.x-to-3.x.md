# Upgrading from Commit Guard 2.x to 3.x

Commit Guard 3.0 is an additive preview release. Existing configuration,
baseline files, hook profiles, and report formats continue to work, but the
JSON schema, default gate behavior, and policy surface have changed.

## Required actions

1. Update report consumers to accept `"schema_version": 3`.
2. Keep `.commit_guard_ignore`; no baseline migration is required.
3. Review the new `balanced` policy defaults before enabling `--gate` in CI.
4. Commit `.commit_guard/triage.yaml` if you use triage; the installer now
   unignores that one file while keeping the rest of `.commit_guard/` ignored.
5. Re-run `./commit-guard install` to refresh the copied engine and hook.

## JSON schema v3

The top-level report schema is now `3`. New finding fields are additive:
`id`, `engine`, `category`, `confidence`, optional columns/end positions,
`fix`, `references`, `code_flows`, `also_reported_by`, rule/pack versions,
and provenance metadata. Unknown fields written by future producers are
preserved under `provenance.unknown` when a report is read and re-emitted.

Consumers that validate against schema 2 must relax the version check or move
to schema 3. Consumers that only read `file`, `line`, `rule_id`, `severity`,
and `fingerprint` need no changes.

## Policy and hooks

The pre-commit and pre-push hooks now pass `--gate`. The default profile is
`balanced`: block new high/critical findings, allow up to 25 new medium and
100 new low findings, and enforce the configured baseline ratchet. Use
`--policy-profile audit` for an observe-only rollout, or `--policy-profile
strict` to block every finding at medium or above.

Policy configuration lives under `[gate]` in `.commit_guard.toml`; a separate
TOML file can be selected with `--policy PATH`. See [POLICY.md](POLICY.md).

To preserve 2.x threshold-only behavior, remove `--gate` from generated hooks
or run with a policy whose `fail_on = "all"` and no budgets. `--soft-fail`
still forces exit code 0 after reporting.

## SARIF and ingested tools

SARIF output remains SARIF 2.1.0. Commit Guard now enriches it with engine,
category, confidence, fixes, and code-flow data. SARIF 2.x and native output
from Semgrep, gitleaks, Trivy, Checkov, and Bandit can be normalized with
`commit-guard ingest`. See [INTEROP.md](INTEROP.md).

## Packaging and rules

- `core.engines` is now part of the installed wheel and the copied
  `.commit_guard/` tree.
- The GitHub Action uses `policy-threshold` for gate threshold overrides. The
  legacy `threshold` input applies only when `gate: false`.
- Bundled Semgrep rule packs remain release-blocked by their upstream license.
  They are unavailable in release artifacts; use the native rules or your own
  Semgrep installation.
- Python 3.11 or newer is required.

## Verification

```bash
./commit-guard doctor
./commit-guard scan --staged --gate --policy-profile audit
./commit-guard check-rules
```
