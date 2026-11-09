# Phase 4 exit review

Phase 4 is the ecosystem phase. This page maps every deliverable and exit
criterion to code, tests, and reproducible commands. It distinguishes what the
repository can prove from what requires an external party.

## Deliverables

| Deliverable | Implementation | Evidence |
|---|---|---|
| Interprocedural taint for JavaScript/TypeScript, Java, and Go | `core/interprocedural.py`, wired into `core/engines/taint_engine.py`; rule metadata in `core/ast_taint.py` | `tests/test_phase4_ecosystem.py`; `benchmarks/accuracy_benchmark.py` cases `javascript-cross-file-wrapper`, `java-interprocedural-wrapper`, `go-interprocedural-wrapper` |
| SCA reachability and VEX import/export | `core/reachability.py`, `core/vex.py`; `--sca-reachability`, `--vex`; `commit-guard vex` | `tests/test_phase4_foundation.py` |
| Signed third-party rule packs | `core/rule_packs.py`; `commit-guard packs` | `tests/test_phase4_ecosystem.py`; `docs/ECOSYSTEM.md` |
| Git-based community registry | `registry.json` reader, local and git sources, digest-pinned installs | `tests/test_phase4_ecosystem.py`; `docs/ECOSYSTEM.md` |
| Local-first AI assistant | `core/ai_assistant.py`; `commit-guard ai` | `tests/test_phase4_foundation.py` |
| Published AI evaluation | `benchmarks/ai_evaluation.py` | `python benchmarks/ai_evaluation.py --json` |
| Native binaries | `scripts/build_native.py`, `.github/workflows/native.yml` | Build is opt-in and requires PyInstaller; CI builds Linux, macOS, and Windows artifacts |
| Public benchmark leaderboard | `benchmarks/leaderboard.py`, `.github/workflows/benchmarks.yml` | Artifacts: accuracy, AI evaluation, latency, leaderboard Markdown/JSON |
| Governance | `GOVERNANCE.md`, `MAINTAINERS.md`, `.github/CODEOWNERS`, `docs/SECURITY-RESPONSE.md` | Roles, quorum, rotation, absence, and security runbook |

## Exit criteria

| Criterion | Status | Evidence |
|---|---|---|
| A security team can replace a hosted scanner for the supported use cases and document why. | Ready for evaluation | The supported surface is local SAST (Python, JS/TS, Java, Go), SCA with reachability and VEX, policy gate, SARIF, SBOM, and signed rule packs. `docs/PHASE4-EXIT.md` is the checklist; a replacing team records its own scope and accepted gaps. |
| Accuracy claims are reproducible by an independent party. | Ready for independent run | Every benchmark is deterministic, offline, and emits JSON. `benchmarks/leaderboard.py` records commit, Python version, and platform. The repository cannot itself prove that an independent party ran it. |
| At least one external contributor maintains a rule pack. | Not yet evidenced | The pack format, signing, registry, CODEOWNERS entry, and revocation process are implemented. This criterion needs a real external maintainer and a released pack; it must not be marked done by the project alone. |
| The release process survives a maintainer absence. | Ready | `GOVERNANCE.md` defines an acting lead, two trained release managers, two key custodians, and patch releases without schema changes. `docs/SECURITY-RESPONSE.md` defines a 48-hour backup handoff. A dry run with a second release manager is still required before claiming it has been exercised. |

## Reproduction commands

```bash
python -m unittest discover -s tests -q
ruff check main.py install_hook.py gui_server.py gui_actions.py gui_page.py core tests benchmarks
mypy main.py install_hook.py gui_server.py gui_actions.py gui_page.py core
python benchmarks/accuracy_benchmark.py --json
python benchmarks/ai_evaluation.py --json
python benchmarks/scan_benchmark.py --json
python benchmarks/leaderboard.py --results-dir . --commit "$(git rev-parse HEAD)"
```

## Known limits

- Interprocedural summaries are name-based and conservative. Ambiguous helper
  names, dynamic dispatch, reflection, and generated code can cause false
  positives or false negatives.
- Java and Go analysis is syntax-driven, not type-resolved.
- Native binaries are convenience artifacts, not the canonical signed release.
- The leaderboard does not compare against commercial products and does not
  claim whole-program precision.
- External rule-pack maintenance and an exercised maintainer-absence dry run
  are organizational evidence, not code, and remain open until a real event
  occurs.
