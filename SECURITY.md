# Security policy

CommitGuard is a security tool that parses untrusted repositories, rule packs,
reports, and lockfiles. We treat vulnerabilities in CommitGuard itself as
security incidents.

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | Yes — security fixes |
| < 2.1 | No |
| 3.x | Not released yet |

When CommitGuard 3.x ships, the latest minor release and the previous minor
release will receive security fixes. Older lines remain supported for at least
six months after a major release unless this table says otherwise.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** if it is available:

<https://github.com/AmrEldhshan/CommitGuard/security/advisories/new>

If private reporting is unavailable, email **amr171516@gmail.com** with the
subject line `CommitGuard security report`.

Do **not** open a public issue, pull request, discussion, or social-media post
containing exploit details before a fix and an advisory are ready.

Please include, when possible:

- affected version, commit, operating system, and Python version;
- the command or configuration used;
- a minimal reproduction in a throwaway repository;
- the impact, including whether secrets, code execution, report integrity, or
  the gate decision are affected;
- whether the issue is already public or being exploited;
- a safe way to contact you and whether you want credit.

Do not include real credentials, personal data, or third-party source code that
you are not allowed to share.

## Response targets

| Stage | Target |
|---|---|
| Acknowledge report | 3 business days |
| Initial triage and severity | 7 business days |
| Coordinated disclosure | 90 days from the report |

The 90-day target is a goal, not a promise that overrides safety. We may agree
to a shorter or longer window when a fix is complex, a release is blocked, or
there is evidence of active exploitation. We will explain the delay and keep
you informed.

## Disclosure process

1. We confirm the report, assign a severity, and identify affected versions.
2. We develop and test a fix, including a regression test and a hostile fixture
   where applicable.
3. We prepare an advisory with affected versions, impact, workarounds, and
   fixed versions.
4. We request a CVE through GitHub Security Advisories or MITRE.
5. We publish the fix, advisory, checksums, and release notes together.
6. We credit the reporter unless they ask to remain anonymous.

If the issue affects a third-party engine, rule corpus, or dependency, we will
coordinate with that project and publish CommitGuard-specific mitigation
guidance. We do not forward your report without asking.

## Security release procedure

- Fixes are developed on a private branch or a GitHub security advisory fork.
- The fix is reviewed for scope and backported to supported lines.
- Tests, lint, type checks, package build, and the benchmark regression gate
  must pass before release.
- The release is published with a changelog entry, checksums, and a GitHub
  Security Advisory.
- A revoked rule pack is disabled and versioned, not silently edited in place.

## Rule-pack revocation

A bad or compromised rule can cause false negatives, false positives, or unsafe
autofix behavior. The process is:

1. Disable or quarantine the rule in the default pack.
2. Add a regression sample that reproduces the problem.
3. Bump the pack version and content digest.
4. Publish a release note and, for serious issues, a security advisory.
5. Tell users how to verify the new digest and whether a baseline needs review.
6. Keep the revoked rule out of release artifacts until the cause is fixed.

Third-party packs follow `rules/PROVENANCE.yaml`. A pack marked
`release-blocked` is not distributed in wheels or source distributions.

## Accidental secrets

If you accidentally post a real credential in an issue, pull request, log, test
fixture, or advisory:

1. **Rotate or revoke the credential immediately.** Removing the message does
   not undo the exposure.
2. Tell the maintainers at `amr171516@gmail.com` so the content can be removed
   quickly.
3. Do not paste the value again, including in a "safe" partial form.

Maintainers remove exposed secrets from issues, logs, fixtures, and release
artifacts when possible. History rewrites are coordinated with affected users
and are not treated as a substitute for rotation.

## Scope

In scope:

- CommitGuard source code, installer, command-line interface, and local GUI;
- built packages, GitHub Action, pre-commit hooks, and release artifacts;
- bundled rule packs and checksums;
- path handling, diff parsing, SARIF/report ingestion, redaction, and the gate
  decision;
- dependency and supply-chain issues that affect CommitGuard users.

Out of scope:

- vulnerabilities found in repositories scanned by CommitGuard;
- vulnerabilities in third-party scanners or engines that CommitGuard invokes;
  report those upstream and notify us if CommitGuard needs a mitigation;
- missing findings, false positives, or rule quality without a security-impact
  explanation;
- attacks that require the user to disable TLS, run unreviewed code, or expose
  the loopback GUI to a network;
- denial-of-service reports that require unbounded local resources without a
  realistic attack path.

## Testing guidelines

- Use a throwaway repository and synthetic data.
- Do not access data that does not belong to you.
- Do not run destructive tests against shared infrastructure.
- Do not exfiltrate source code, secrets, tokens, or personal data.
- Stop once you have demonstrated the issue; do not expand the impact.

We will not pursue legal action for good-faith research that follows this
policy and applicable law.

## More information

- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Rule provenance: [`rules/PROVENANCE.yaml`](rules/PROVENANCE.yaml)
- Machine-readable contact: [`security.txt`](security.txt) and
  [`.well-known/security.txt`](.well-known/security.txt)
- Release and CI expectations: [`docs/CI.md`](docs/CI.md)
