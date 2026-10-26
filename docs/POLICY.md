# Policy v1

Commit Guard policy turns findings into a deterministic pass/fail decision. It
is evaluated after baseline matching and triage suppression.

## Configuration

```toml
[gate]
enabled = true
profile = "balanced"
threshold = "high"
fail_on = "new"
ratchet = true
max_new = { critical = 0, high = 0, medium = 25, low = 100 }

[gate.budgets]
"*" = { critical = 0, high = 0, medium = 25, low = 100 }
".py" = { critical = 0, high = 0, medium = 10, low = 50 }
secret = { critical = 0, high = 0, medium = 0, low = 0 }
```

`--policy PATH` selects a standalone policy file; `[gate]` in
`.commit_guard.toml` is used otherwise. `--policy-profile
strict|balanced|audit` overrides the profile. `--threshold` overrides the
blocking severity for that run. In the GitHub Action, use
`policy-threshold` when `gate: true`; the legacy `threshold` input applies only
when `gate: false`.

## Profiles

| Profile | Threshold | Fail on | Ratchet | Default budgets |
|---|---|---|---|---|
| `strict` | `medium` | all | on | zero new findings |
| `balanced` | `high` | new | on | 0 critical/high, 25 medium, 100 low |
| `audit` | `info` | new | off | no enforcement |

`audit` reports the decision but always passes. Use it for rollout and
baseline measurement.

## Decisions

- `new_findings` counts findings whose `baseline_state` is not `unchanged`.
- `blocking` counts findings at or above the threshold (and all findings when
  `fail_on = "all"`).
- Exceeding a per-severity, path, or category budget fails the gate.
- With `ratchet = true`, any new finding at or above the threshold adds a
  ratchet reason in addition to the finding itself; callers can also supply a
  baseline total to block growth from that total. Removing baseline entries is
  still an explicit review/baseline operation.
- Suppressing triage states (`accepted`, `false_positive`, `wont_fix`) remove
  findings before policy evaluation. Expired entries do not suppress.
- A triage entry marked `fixed` still showing up is a policy failure.

## Commands

```bash
./commit-guard gate --staged
./commit-guard gate --report report.json --format json
./commit-guard policy validate
./commit-guard policy explain RULE_ID
./commit-guard scan --gate --policy-profile audit
```

Exit codes are `0` for pass, `1` for a policy or threshold failure, and `2`
for an operational error.

## Triage

Triage state is stored in `.commit_guard/triage.yaml` and is intended to be
committed. Suppressing states require an owner and reason. Use `fixed` to
assert a fingerprint should disappear, and `--include-expired`/audit reporting
to find stale decisions.

```bash
./commit-guard triage list
./commit-guard triage set FINGERPRINT --state accepted --owner team --reason "test fixture"
./commit-guard triage audit
./commit-guard triage prune --dry-run
```
