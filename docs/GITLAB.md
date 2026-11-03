# GitLab Merge Request Integration

CommitGuard has the same summary and inline-suggestion flow on GitLab as on
GitHub. `--platform` accepts `auto`, `github`, or `gitlab`; `auto` selects
GitLab when `GITLAB_CI=true` or `CI_MERGE_REQUEST_IID` is present.

## Required variables

| Variable | Purpose |
|---|---|
| `CI_API_V4_URL` | GitLab API base URL (automatic in GitLab CI). |
| `CI_PROJECT_ID` | Numeric project ID (automatic). |
| `CI_MERGE_REQUEST_IID` | Merge request IID (automatic in MR pipelines). |
| `CI_COMMIT_SHA` | Head commit for inline positions (automatic). |
| `CI_MERGE_REQUEST_DIFF_BASE_SHA` | Diff base (automatic when available). |
| `CI_MERGE_REQUEST_TARGET_BRANCH_SHA` | Diff start (automatic when available). |
| `GITLAB_TOKEN` | Token with `api` scope; `CI_JOB_TOKEN` is used as a fallback. |

When the diff refs are unavailable, CommitGuard asks the merge request versions
endpoint for the latest `base_sha`, `start_sha`, and `head_sha`.

## Pipeline example

```yaml
commitguard:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install commit-guard
  script:
    - commit-guard scan --diff "$CI_MERGE_REQUEST_DIFF_BASE_SHA...$CI_COMMIT_SHA"
        --format gitlab --report-path gl-code-quality-report.json
        --create-pr --review-pr --platform gitlab
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

`--create-pr` publishes or updates one marker-based merge request note.
`--review-pr` posts auto-fix suggestions as merge request discussions. Secret
values and raw flagged code are never included in either surface.

## Offline OSV snapshots

Signed offline snapshots use an HMAC-SHA256 sidecar:

```bash
export COMMITGUARD_OSV_SIGNING_KEY=...
python scripts/sign_osv_snapshot.py .commit_guard_osv.json
commit-guard scan --sca --sca-require-signature
```

The sidecar is `<snapshot>.sig`. Without `--sca-require-signature`, an unsigned
snapshot is accepted for local development; a present but mismatched signature
is always rejected.
