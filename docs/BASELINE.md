# CommitGuard 2.1.0 baseline

Measured on 2026-10-26 from the working tree that includes the recorded GUI
changes. The intended baseline tag is `v2.1.0-baseline`.

| Item | Value |
|---|---|
| Version | 2.1.0 |
| Last commit before baseline packaging | `8ad2b28` (`fix the gui`) |
| Working-tree changes included | `gui_page.py`, `tests/test_gui_page.py`, removal of `AegisPlan.md` |
| Test command | `python -m unittest discover -s tests -v` |
| Tests before Phase 0 | 205 passed, 0 failed |
| Tests after Phase 0 provenance checks | 209 passed, 0 failed |
| Active rules | 342 |
| Skipped rule entries | 2,059 |
| Corpus samples | 25 |
| Schema/corpus issues | 0 |
| Runtime dependency | PyYAML>=6.0 |
| Local Python used for measurement | 3.14.7 |
| CI Python matrix | 3.11, 3.12, 3.13 |

Reproduce the rule numbers with:

```bash
python main.py --list-rules
python main.py --check-rules
python -m unittest discover -s tests -v
```

## Baselines versus the master plan

The master plan records 194 tests and 340 active rules from its 2026-10-24
measurement. The working tree now has 205 tests and 342 active rules because the
GUI work and the current rule set are included. The measured values above are
the authoritative baseline for this checkout.

## Tagging

The baseline tag must point at a commit that contains the recorded GUI work,
not at a dirty tree. Prefer a GUI-only baseline commit before the Phase 0
hygiene files, so the tag identifies the measured 2.1.0 state:

```bash
git add gui_page.py tests/test_gui_page.py
git commit -s -m "chore: record CommitGuard 2.1.0 GUI baseline"
git tag -a v2.1.0-baseline -m "CommitGuard 2.1.0 baseline"
```

Then commit the Phase 0 hygiene changes separately. If the tag is created after
Phase 0 is committed, label it as the Phase 0 exit tag instead of a pure 2.1.0
baseline. Do not move an existing baseline tag.
