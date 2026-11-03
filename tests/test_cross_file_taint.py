from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.ast_taint import scan_python_taint
from core.engines import ScanContext, TaintEngine
from core.git_diff import DiffLine


class CrossFileTaintTests(unittest.TestCase):
    def test_helper_sink_receives_taint_from_caller(self) -> None:
        files = {
            "db.py": [
                "def run_query(cursor, request):",
                "    user_id = request.args.get('id')",
                "    cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            ],
            "app.py": [
                "from db import run_query",
                "",
                "def view(request, cursor):",
                "    run_query(cursor, request)",
            ],
        }
        result = scan_python_taint(files, {"app.py": {4}})
        self.assertEqual(len(result.matches), 1)
        finding = result.matches[0].finding
        self.assertEqual(finding.rule_id, "cg-python-ast-sqli-taint")
        self.assertEqual(finding.file, "app.py")
        self.assertEqual(finding.line_number, 4)

    def test_helper_returning_source_taints_caller_sink(self) -> None:
        files = {
            "auth.py": [
                "def get_id(request):",
                "    return request.args.get('id')",
            ],
            "app.py": [
                "from auth import get_id",
                "",
                "def view(request, cursor):",
                "    user_id = get_id(request)",
                "    cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            ],
        }
        result = scan_python_taint(files, {"app.py": {4, 5}})
        self.assertTrue(result.matches)
        self.assertEqual(
            result.matches[0].finding.rule_id, "cg-python-ast-sqli-taint"
        )

    def test_engine_discovers_sibling_modules_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "db.py").write_text(
                "def run_query(cursor, request):\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n",
                encoding="utf-8",
            )
            app = root / "app.py"
            app.write_text(
                "from db import run_query\n"
                "\n"
                "def view(request, cursor):\n"
                "    run_query(cursor, request)\n",
                encoding="utf-8",
            )
            lines = app.read_text(encoding="utf-8").splitlines()
            context = ScanContext(
                repo_root=root,
                diff_lines=(DiffLine("app.py", 4, "    run_query(cursor, request)"),),
                changed_paths=("app.py",),
                files={"app.py": lines},
                file_lines={"app.py": lines},
            )
            result = TaintEngine().run(context)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.findings[0].rule_id, "cg-python-ast-sqli-taint"
        )


if __name__ == "__main__":
    unittest.main()
