# General rule packs

These packs provide broad, source-agnostic coverage that is not tied to a
single CommitGuard feature. They use the same native schema as
`rules/custom_rules.yaml` and are loaded automatically by
`core/rule_loader.py`.

## Layout

| Path | Source | Contents |
|---|---|---|
| `web.yaml` | Project-authored | SSRF, path traversal, open redirect, SSTI, NoSQL injection, XXE, CORS, cookie, and upload heuristics. |
| `authz.yaml` | Project-authored | Mass assignment, IDOR, privilege escalation, business-logic, timing, and TOCTOU review prompts. |
| `deserialization.yaml` | Project-authored | Unsafe pickle/torch/joblib/YAML/.NET/Java/Node deserialization and dangerous expression evaluation. |
| `supply_chain.yaml` | Project-authored | Install-script execution, GitHub Actions `pull_request_target`, and workflow permission issues. |
| `devskim/` | Microsoft DevSkim | Generated MIT-licensed language/framework checks. Do not edit by hand. |

## Updating the DevSkim pack

The DevSkim files are generated from a pinned upstream revision:

```bash
python scripts/fetch_general_rules.py
python scripts/fetch_general_rules.py --dry-run
```

The converter deliberately skips rules that need DevSkim's structured
analyzers or language exclusions, because approximating them as plain regexes
would produce false positives. Re-running the script is deterministic; update
`rules/PROVENANCE.yaml` and `THIRD_PARTY_NOTICES.md` if the pinned revision
changes.

## Authoring notes

- Keep heuristic rules at `medium` or `low` severity unless the pattern itself
  is a direct dangerous sink.
- Use `confidence` to distinguish a direct sink (`high`) from a review prompt
  (`low`). `category` should be one of the values in `core/findings.py`.
- Language filters may use extensions or filename tokens such as `dotenv`,
  `pip-requirements`, `packages-config`, `csproj`, and `config`.
- Patterns run one line at a time. Use `context` for bounded nearby-line checks.
- Add a positive/negative sample to `rules/corpus.yaml` for every new rule.
