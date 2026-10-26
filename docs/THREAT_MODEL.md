# Threat model for CommitGuard itself

CommitGuard runs inside a developer's repository, reads untrusted content, and
decides whether a change may proceed. This document describes the assets,
trust boundaries, and controls for the tool, not for the code it scans.

## Assets

- Source code, diffs, commit history, and repository paths.
- Secrets that may already be present in code or history.
- GitHub/GitLab tokens, provider keys, and CI credentials.
- Rule packs, checksums, snapshots, and plugin manifests.
- Reports, baselines, triage data, SBOMs, audit logs, and gate decisions.
- Release artifacts, signing keys, and package metadata.
- User trust in the gate result.

## Adversaries and trust boundaries

| Adversary | Capability | Trust boundary |
|---|---|---|
| Malicious repository author | Controls files, paths, symlinks, diffs, lockfiles, configuration, comments, and branch names | Repository content is untrusted. |
| Malicious rule-pack author | Controls YAML/TOML, regexes, metadata, and fix patterns | Rule packs are untrusted until verified. |
| Compromised third-party tool | Emits hostile SARIF, JSON, or native output | Ingested reports are untrusted. |
| Network attacker | Intercepts optional online lookups | The network is untrusted; TLS and checksums are required. |
| Malicious plugin | Would run arbitrary code in-process | Plugins are untrusted and must be out-of-process by default. |
| Compromised dependency | Supply-chain compromise of PyYAML or another runtime dependency | Dependencies are pinned, scanned, and tracked in notices. |
| Insider or compromised CI | Can edit policy, baselines, or workflow files | Changes are reviewed, audited, and token-scoped. |
| LLM prompt injection | Instructions embedded in code, comments, or data | Model output is untrusted; no automatic actions. |

## Controls

- Canonicalize and validate paths; reject absolute paths, `..`, and paths
  outside the repository.
- Define symlink behavior and never follow a symlink outside the repository.
- Enforce limits on file size, diff size, line length, nesting depth, and
  finding count.
- Invoke subprocesses with argument lists, never a shell; scrub credentials from
  the environment where possible.
- Apply timeouts to parsers and engines; kill process groups on cancellation.
- Validate SARIF, JSON, YAML, and rule schemas before use; never execute URLs or
  commands from them.
- Escape terminal output and HTML; do not trust control characters in paths.
- Redact secrets by default in every output path, including errors and logs.
- Do not store secrets in configuration, reports, caches, history, or GUI state.
- Verify signatures and checksums for downloaded engines, packs, snapshots, and
  plugins.
- Treat plugin output as untrusted and cap it.
- Never auto-load plugins or rules from a scanned repository.
- Bind the local GUI to loopback and use a strict content-security policy.
- Prove offline behavior in CI with a network-disabled test when practical.
- Keep `rules/PROVENANCE.yaml` current and block release of unreviewed packs.

## Abuse cases to test

- A repository with a huge file, a deeply nested YAML rule, or a catastrophic
  regular expression.
- A symlink that points outside the repository.
- A file name containing terminal control characters.
- A SARIF file with excessive results or a cyclic structure.
- A rule pack that tries to read `/etc/passwd` or spawn a process.
- A plugin that hangs, allocates unbounded memory, or writes indefinitely.
- A prompt-injection comment that asks an AI assistant to exfiltrate a file.
- A malicious lockfile that triggers pathological version parsing.
- A diff that deletes or renames thousands of files.
- A report with a secret in a message, snippet, or stack trace.

## Known limitations

- CommitGuard is not a sandbox. It runs with the permissions of the user who
  invokes it.
- Regex scanning cannot prove the absence of a vulnerability.
- Regexes are evaluated by Python's `re` module; pathological patterns must be
  bounded by timeouts and limits.
- The local GUI is a loopback developer console, not a multi-user service.
- Third-party findings are only as trustworthy as the tool that produced them.

## Reporting

Report vulnerabilities through the process in [`SECURITY.md`](../SECURITY.md).
Do not publish exploit details before a fix and advisory are ready.
