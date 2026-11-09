# Maintainers

Role assignments use organization teams so access can be rotated without
editing this file. The lead maintainer is also listed in the README.

| Role | Holder | Team |
|---|---|---|
| Lead maintainer | Amr Khaled Ahmed ([@AmrEldhshan](https://github.com/AmrEldhshan)) | `@CommitGuard-Sec/lead-maintainers` |
| Maintainer council | Project maintainers | `@CommitGuard-Sec/maintainers` |
| Release managers | Rotating pair | `@CommitGuard-Sec/release-managers` |
| Security response team | At least two maintainers | `@CommitGuard-Sec/security-response` |
| Rule-pack maintainers | Per-pack owners | `@CommitGuard-Sec/rule-packs` |

## Responsibilities

- **Lead maintainer:** product direction, final tie-break, external
  representation, and acting release manager when the rotation is unavailable.
- **Maintainer council:** design review, maintainer appointments, governance
  changes, and escalation.
- **Release managers:** run the release checklist, verify signed artifacts,
  publish checksums and SBOMs, and coordinate with the security response team.
- **Security response team:** acknowledge reports, triage severity, develop and
  backport fixes, request CVEs, and publish advisories.
- **Rule-pack maintainers:** own pack rules, provenance entries, tests,
  digests, and revocation notices.

## Rotation

Release managers rotate each release. The outgoing release manager confirms
that the incoming manager has repository release permissions, access to the
signing-key custodian process, and has completed one dry run.

## Emeritus

Emeritus maintainers keep credit for their contributions and may return through
the normal nomination process. See [GOVERNANCE.md](GOVERNANCE.md).
