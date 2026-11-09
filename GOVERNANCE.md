# Governance

CommitGuard is an Apache-2.0 project maintained in public. This document
defines who decides, how decisions are recorded, and how the project keeps
shipping when an individual maintainer is unavailable.

## Principles

- Security and user safety come before feature velocity.
- Decisions happen in issues, pull requests, or meeting notes that anyone can
  read. Private channels are reserved for embargoed security work.
- The project prefers reversible changes, small commits, and tests over
  undocumented process.
- No single person is a release or incident bottleneck.

## Roles

| Role | Responsibilities | Appointment |
|---|---|---|
| Lead maintainer | Product direction, final tie-break, external representation. | Current project creator; successor chosen by the council. |
| Maintainer council | Reviews design and policy changes, approves new maintainers, resolves escalated disputes. | Maintainers with sustained review history, approved by the council. |
| Release manager | Cuts releases, verifies artifacts and signatures, publishes advisories with the security team. | Rotates every release; at least two people are trained. |
| Security response team | Triages private reports, coordinates fixes and disclosure, maintains the advisory record. | At least two maintainers plus the lead maintainer. |
| Rule-pack maintainers | Own a pack's rules, provenance, tests, and revocation process. | Any contributor who maintains a pack through two releases. |
| Contributors | Submit code, rules, docs, and bug reports under the DCO. | Open to everyone. |

Current role holders are listed in [MAINTAINERS.md](../MAINTAINERS.md) and
enforced by [`.github/CODEOWNERS`](../.github/CODEOWNERS).

## Decision making

1. **Lazy consensus.** Routine changes merge when a maintainer approves and CI
   passes. Silence for three business days is not a block on a small fix.
2. **Design review.** Changes to the finding schema, config schema, CLI
   contract, engine protocol, rule format, or release process need one council
   approval beyond the author.
3. **Council vote.** When consensus fails, the council votes. A simple majority
   wins; the lead maintainer breaks ties. Security response team members may
   veto a release that would ship an unresolved critical vulnerability.
4. **Record the decision.** Link the issue or pull request in the changelog or
   the relevant design document. Verbal decisions do not exist.

## Adding and removing maintainers

- A contributor is eligible after sustained, constructive review and at least
  three merged changes across code, tests, and docs.
- Any maintainer may nominate; the council approves by majority.
- A maintainer may step down at any time.
- Inactive maintainers move to emeritus after six months without review or
  release work. Emeritus maintainers keep credit and may return.
- Removal for cause requires a council supermajority and a written rationale
  shared with the affected person before publication, except where doing so
  would expose a reporter or an active incident.

## Release management and continuity

- Two release managers are trained at all times. The release checklist lives in
  [RELEASING.md](RELEASING.md).
- Release credentials and signing keys are held in organization secrets with at
  least two custodians. No release depends on one person's laptop.
- If the lead maintainer is unavailable for more than 14 days, the council
  designates an acting lead. Releases continue under the normal checklist.
- If fewer than two council members are available, the release manager may ship
  patch and security releases that contain no schema or policy changes.

## Security response

The security response team follows [SECURITY.md](../SECURITY.md) and
[SECURITY-RESPONSE.md](SECURITY-RESPONSE.md). At least two people must be able
to open a private advisory, build a fix, and publish a release. Security
decisions are documented in the advisory even when the discussion is private.

## Rule packs and the registry

- Every pack records provenance, license, and a content digest.
- A pack maintainer can release independently, but the security response team
  can quarantine a pack and publish a revocation notice.
- Registry changes are reviewed like code. A registry entry is pinned to a
  commit and digest; it is never a mutable pointer to `main`.

## Changes to this document

Governance changes need a council majority and a 14-day public comment period,
except for emergency changes needed to run an active security response. Record
emergency changes in the next release notes.
