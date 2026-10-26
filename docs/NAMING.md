# Naming, package identity, and availability

**Status:** Phase 0 record, updated 2026-10-26.

The product name is **CommitGuard** and is not changing. The primary CLI
command is `commit-guard`; `cg` is the planned shorthand for the same command
surface and is not shipped yet. The target PyPI distribution is `commit-guard`.
`commit-guard-sast` is the documented fallback if the primary name cannot be
reserved.

## PyPI availability check

Both names were queried against the public PyPI JSON API on 2026-10-26:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/commit-guard/json
# 404
curl -sS -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/commit-guard-sast/json
# 404
```

| Distribution | HTTP result | Meaning | Selected |
|---|---|---|---|
| `commit-guard` | 404 | no project exists; name appears available | primary |
| `commit-guard-sast` | 404 | no project exists; name appears available | fallback |

A 404 is a point-in-time availability check, not a reservation. PyPI has no
reservation API: a name is claimed by the first successful upload. **No upload
has been made.** The project owner must claim `commit-guard` with the first
release, or with a `0.0.0` placeholder if the name needs protection before the
first real release. Do not upload any artifact that fails the release gates in
`docs/CI.md`, `SECURITY.md`, and `rules/PROVENANCE.yaml`.

The fallback is reserved only on paper. If the primary name is taken between
this check and the first upload, record the conflict here and use
`commit-guard-sast`; do not add rename-compatibility code for the old name.

## Trademark check

No trademark clearance search has been completed. "CommitGuard" is used as a
project name, not a claim of registered trademark rights. Complete a search in
the relevant jurisdictions before any paid product, company formation, or
public launch that relies on the name.

## Canonical surfaces

| Surface | Standard |
|---|---|
| Product | CommitGuard |
| CLI | `commit-guard`; `cg` shorthand is planned |
| PyPI | `commit-guard`; `commit-guard-sast` only if the primary is unavailable |
| Configuration | `.commit_guard.toml` |
| Local state | `.commit_guard/` |
| Baseline | `.commit_guard_baseline` |
| Explicit ignore list | `.commit_guard_ignore` |
| Environment variables | `COMMIT_GUARD_*` |
| Inline suppression | `commit-guard-ignore` |
| GitHub Action | `AmrEldhshan/commit-guard-action@v1` (target) |
| Report paths | `commit_guard_report.*` or an explicitly configured path |

Do not add rename detection, dual-read configuration, or legacy-name aliases.
