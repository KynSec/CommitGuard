from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.scan_benchmark import benchmark, build_fixture


class BenchmarkTests(unittest.TestCase):
    def test_generated_fixture_measures_a_clean_staged_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = build_fixture(Path(directory) / "repo", files=4, lines=8)
            result = benchmark(repo, iterations=1, timeout=60)
        self.assertEqual(result["iterations"], 1)
        self.assertGreaterEqual(float(result["median_ms"]), 0)
        self.assertLess(float(result["median_ms"]), 60_000)
        self.assertIsInstance(result["findings"], int)


if __name__ == "__main__":
    unittest.main()
