# Determinant scan profiles

Scan profiles let you name a repeatable selection of **what to scan** and **which rules to run**. They live in `rules/scan_profiles.yaml`, next to the bundled rule files, and are available in the CLI, the GUI, and when Commit Guard is installed from PyPI.

A profile is not a second rules format. It only selects from the rules already loaded by Commit Guard, so the same rule ids, severities, and sources work everywhere.

## Quick start

List the profiles that are currently available:

```bash
python main.py --list-profiles
```

Scan with a named profile:

```bash
python main.py --profile app-code
```

Scan only `src/` and `tests/` while using the `python-security` rules:

```bash
python main.py --profile python-security --include "src/**" --include "tests/**"
```

Inspect the JSON report to see exactly what was selected:

```json
{
  "selection": {
    "profile": "app-code",
    "mode": "repo",
    "paths": {"include": ["src/**", "tests/**"], "exclude": ["**/generated/**"]},
    "rules": {"sources": ["custom", "python_ast"], "include": [], "exclude": [], "severities": []}
  }
}
```

## File location

The default file is:

```text
rules/scan_profiles.yaml
```

`rules/` is resolved the same way as the rule database: the installed bundle, the engine directory, or the repository's rules directory, depending on how you run Commit Guard. To use a different file, set `profiles_file` in `.commit_guard.toml` or pass `--profiles-file`:

```bash
python main.py --profiles-file config/team-profiles.yaml --profile release-gate
```

A missing default file simply means no profiles are defined. A missing file passed explicitly with `--profiles-file` is an error.

## Schema

```yaml
version: 1

profiles:
  profile-name:
    description: Human-readable summary shown in the GUI.
    mode: inherit          # inherit | staged | repo
    paths:
      include:             # optional; empty means every path
        - "src/**"
        - "tests/**"
      exclude:
        - "**/generated/**"
    rules:
      sources:             # optional; empty means every source
        - gitleaks
        - custom
        - python_ast
      include:             # optional rule-id globs; empty means every rule
        - "cg-python-*"
      exclude:
        - "semgrep-*"
      severities:          # optional; empty means every severity
        - critical
        - high
```

### `mode`

| Value | Behavior |
| --- | --- |
| `inherit` | Use the normal scan mode: explicit CLI mode, otherwise staged changes. This is the default. |
| `staged` | Scan staged changes, equivalent to `--staged`. |
| `repo` | Scan the whole working tree, equivalent to `--all`. |

An explicit CLI mode still wins over a profile. For example, `--profile app-code --diff main...HEAD` scans the diff instead of the profile's whole-tree mode.

### `paths.include` and `paths.exclude`

Paths can be files or directories. Globs use the same matcher as configuration excludes:

- `src/**` matches everything below `src/`.
- `tests/*.py` matches Python files directly inside `tests/`.
- `/README.md` anchors the match at the repository root.
- `!src/vendor/**` re-includes a path after an earlier exclude.
- Matching is case-insensitive and uses `/` separators.

Include patterns are applied first. Excludes are applied last. Excludes are **additive**: the profile's excludes, `.commit_guard.toml` excludes, and `--exclude` values are all combined. This keeps the built-in safety exclusions from being accidentally dropped.

Explicit `--include` values replace the profile's include list; they are not appended to it.

### `rules.sources`

Available sources:

- `gitleaks`
- `custom`
- `nuclei`
- `devskim`
- `semgrep` (matches every `semgrep:*` source)
- `semgrep:semgrep_python` (matches one semgrep database)
- `python_ast`
- `javascript_ast`

Explicit `--rule-source` values replace the profile's source list.

### `rules.include` and `rules.exclude`

Rule patterns are shell-style globs matched against the rule id, such as `gitleaks-aws-access-token`, `cg-python-subprocess-shell`, or `semgrep-python-eval`. `include` keeps only matching rules. `exclude` removes matching rules after includes are applied.

Explicit `--rule` values replace the profile's include list. Explicit `--skip-rule` values are added to the profile's exclude list.

### `rules.severities`

Allowed values are `critical`, `high`, `medium`, `low`, and `info`. Explicit `--rule-severity` values replace the profile's severity list.

## Precedence

The effective selection is built in this order:

1. Start with the selected profile.
2. Explicit CLI or GUI values replace profile includes, sources, rule includes, and severities.
3. Excludes are additive: profile, configuration, and CLI/GUI excludes are combined.
4. Configuration path excludes are always applied in addition to the selection.

This means a profile provides a safe default, while the command line can narrow or redirect a single run without editing the file.

## Bundled profiles

The shipped file contains these starting points:

| Profile | Purpose |
| --- | --- |
| `default` | No path or rule restriction; keeps the normal scan mode. |
| `full-repo` | Scans the whole working tree with every rule. |
| `app-code` | Scans `src/` and `tests/` with secret, custom, and Python AST rules. |
| `secrets-only` | Scans everything but keeps only secret-detection sources. |
| `python-security` | Scans Python paths with Python-oriented rules. |
| `sast-high` | Keeps high and critical static-analysis findings across the repository. |

Edit the file directly to add team-specific profiles. Restart the GUI or run `--list-profiles` again to pick up changes.

## CLI reference

| Flag | Purpose |
| --- | --- |
| `--list-profiles` | Print available profiles and exit. |
| `--profile NAME` | Use a named profile from `rules/scan_profiles.yaml`. |
| `--profiles-file PATH` | Load profiles from a specific file. |
| `--include GLOB` | Only scan matching files or directories. Repeatable. |
| `--exclude GLOB` | Skip matching files or directories. Repeatable and additive. |
| `--rule ID_GLOB` | Only run matching rule ids. Repeatable and replaces profile includes. |
| `--skip-rule ID_GLOB` | Skip matching rule ids. Repeatable and additive. |
| `--rule-source SOURCE` | Only run rules from a source. Repeatable and replaces profile sources. |
| `--rule-severity LEVEL` | Only run rules at a severity. Repeatable and replaces profile severities. |
| `--staged` | Scan staged changes, or use it with a profile to force staged mode. |

All selection flags work with Markdown, JSON, SARIF, JUnit, GitLab, Checkstyle, and HTML reports. The Markdown and JSON reports include a `selection` block so a reviewer can see exactly which profile, paths, and rules produced the result.

## GUI

Open the **Scan** tab and use the **Determinant selection** card:

1. Choose a **Scan profile**.
2. Optionally add include and exclude paths.
3. Optionally narrow the run with **Only rules**, **Skip rules**, **Rule sources**, or **Rule severities**.
4. Choose **Profile-defined mode** in the scan mode selector to let the profile decide between staged and whole-repository scanning.

The **Profiles** tab shows this guide inside the GUI, including the active profile file path. The same profile list is used by the CLI, so a selection tested in the GUI can be reproduced with the printed command.

## PyPI and zipapp installation

The profile file ships inside the installed rules package, and this guide ships in the `commit_guard_docs` package. Both are available after:

```bash
pip install commit-guard
commit-guard --list-profiles
```

The standalone zipapp includes the same files, so profiles and the GUI guide work without a source checkout.

If you install from PyPI and want repository-specific profiles, edit the installed `rules/scan_profiles.yaml` or point `--profiles-file` at a file in your repository. Prefer the repository file for team settings that should be version-controlled.

## Validation and troubleshooting

- An unknown profile name lists every available profile.
- Invalid YAML, unknown modes, and invalid severities produce a clear error before scanning starts.
- Empty includes mean "all paths"; empty rule filters mean "all rules".
- If a profile selects no rules, the scan completes with no findings for that selection. Use `--list-profiles` and the JSON `selection` block to confirm the filters.
- Profiles affect selection only. Enforcement thresholds remain controlled by `--threshold`, the policy profile, and `.commit_guard.toml`.
