# Security response runbook

This is the internal runbook for the security response team. The public policy
is [SECURITY.md](../SECURITY.md); this page covers who does what and how the
process survives an absent maintainer.

## Team

- At least two maintainers must hold private-advisory access.
- The release manager on rotation is the release contact for the incident.
- The reporter is a partner, not an adversary. Protect their identity and data.

## Severity and targets

| Severity | Examples | Acknowledge | Fix target |
|---|---|---|---|
| Critical | Code execution in the scanner, secret exfiltration, unsigned update accepted, gate bypass by default config | 1 business day | 7 days |
| High | Report integrity, path traversal writing outside the repo, signed-pack verification bypass | 2 business days | 14 days |
| Medium | Denial of service with a realistic local trigger, unsafe autofix, redaction bypass | 3 business days | 30 days |
| Low | Hardening, defense in depth, documentation gap with limited impact | 5 business days | Next minor |

The 90-day coordinated-disclosure goal from `SECURITY.md` is the outside date,
not a reason to wait when a fix is ready.

## Runbook

1. **Acknowledge.** Reply privately, assign an incident lead and a backup, and
   open a GitHub security advisory.
2. **Triage.** Reproduce in a throwaway repository. Record affected versions,
   attack preconditions, and whether the gate decision or secret handling is
   affected. Do not ask the reporter to run destructive tests.
3. **Contain.** If a rule pack or registry entry is involved, quarantine it and
   publish a revocation notice. If a release artifact is affected, mark it
   withdrawn before publishing details.
4. **Fix.** Add a regression test and a hostile fixture. Keep the fix scoped;
   avoid unrelated refactors in the security branch.
5. **Review.** A second maintainer reviews the fix and the test. The release
   manager verifies the build, lint, type checks, and benchmark gate.
6. **Release.** Publish the fix, advisory, checksums, and SBOMs together.
   Backport to every supported line.
7. **Disclose.** Credit the reporter unless they decline. Publish the advisory
   at the agreed time even if the reporter stops responding, after documenting
   the attempts.
8. **Learn.** Write a short postmortem within 14 days: timeline, root cause,
   detection gap, and one concrete preventive action with an owner.

## Maintainer absence

- The incident lead must name a backup in the advisory thread on day one.
- If the lead is unavailable for 48 hours, the backup becomes lead without a
  new vote.
- If the release manager is unavailable, the lead maintainer or another trained
  release manager runs the checklist.
- If fewer than two team members are available, the council may temporarily
  grant advisory access to a trained maintainer. Record the grant in the
  advisory and revoke it after the incident.

## Rule-pack incidents

1. Remove or disable the rule in the default pack.
2. Add a failing regression sample.
3. Bump the pack version and digest; sign the new pack.
4. Publish a revocation notice naming the affected versions and digests.
5. Keep the revoked pack out of wheels, sdists, zipapps, containers, and the
   registry index.

## Evidence

Keep the reproduction, affected-version list, decision log, and release links
in the private advisory. Publish only what users need to assess risk and verify
the fix. Never paste real credentials into the advisory.
