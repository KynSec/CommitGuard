# Benchmark Card and Limitations

This page is the public benchmark card for CommitGuard 3.x. It records what the
default local gate measures, the fixed-commit accuracy corpus, and the cases
where the results must not be over-read.

## Staged-diff latency

| Item | Value |
|---|---|
| Fixture | 120 files x 20 added lines |
| Rule set | Bundled native rules, warm parsed-rule cache |
| Default gate command | `python benchmarks/scan_benchmark.py --iterations 3 --max-median-ms 2000` |
| CI regression limit | 2000 ms median |
| Last recorded median | ~990 ms (see [BASELINE.md](BASELINE.md)) |

Latency varies with disk cache, Python minor version, and the number of
matching rules. The benchmark is a regression guard, not a cross-tool
leaderboard.

## Fixed-commit accuracy corpus

`benchmarks/accuracy_benchmark.py` scans seeded vulnerable files and their
fixed counterparts in two temporary repositories. A case passes only when the
expected stable rule fires on the vulnerable file and does not fire on the
fixed file.

Supported CWE subset:

| Case | CWE | Stable rule |
|---|---|---|
| Python SQL injection | CWE-89 | `cg-python-ast-sqli-taint` |
| Python shell injection | CWE-78 | `cg-python-ast-shell-taint` |
| Python SSRF | CWE-918 | `cg-python-ast-ssrf-taint` |
| Python path traversal | CWE-22 | `cg-python-ast-path-traversal-taint` |
| Python XSS/SSTI | CWE-79 | `cg-python-ast-xss-taint` |
| JavaScript code execution | CWE-95 | `cg-js-ast-code-exec-taint` |
| Python cross-file wrapper | CWE-89 | `cg-python-ast-sqli-taint` |

Reproduce:

```bash
python benchmarks/accuracy_benchmark.py
python benchmarks/accuracy_benchmark.py --json --output accuracy-report.json
```

The corpus is intentionally small and deterministic. It covers the rules that
are documented as stable, not every bundled rule.

## What the benchmark does not claim

- It is not a comparison against commercial SAST or SCA products.
- It does not measure whole-program taint precision on large monorepos.
- The synthetic fixture does not represent every framework, ORM, or template
  engine. Unknown frameworks can produce false negatives.
- The JavaScript/TypeScript taint engine is syntax-driven and does not perform
  full type resolution; aliasing through arbitrary abstractions is out of
  scope for Phase 2.
- Python cross-file summaries match functions by name. Ambiguous helpers with
  the same name in unrelated modules can increase false positives.
- Offline SCA depends on the freshness of the supplied OSV snapshot. Signed
  snapshots prove integrity, not completeness or currency.
- The latency fixture uses generated Python files. Results for large binary
  trees, monorepos, or cold caches will differ.
- The accuracy corpus is a floor for regressions, not a published precision or
  recall score on an independent holdout set.

Report benchmark regressions with the exact command, Python version, and
platform so the result can be reproduced.
