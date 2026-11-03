from __future__ import annotations

import os
import re
import unittest
from types import SimpleNamespace
from unittest import mock

from core.gitlab_mr import (
    SUMMARY_MARKER,
    GitLabClient,
    GitLabOptions,
    build_gitlab_inline_suggestions,
    build_gitlab_summary,
    gitlab_options_from_environment,
    publish_gitlab_inline_suggestions,
    publish_gitlab_summary,
)


def finding() -> SimpleNamespace:
    return SimpleNamespace(
        file="app.py",
        line_number=3,
        rule_id="fix-verify",
        description="TLS verification disabled",
        severity="medium",
        blocked=True,
        flagged_code="requests.get(url, verify=False)",  # commit-guard-ignore: cg-python-tls-verify-disabled
        redacted_code="requests.get(url, verify=False)",  # commit-guard-ignore: cg-python-tls-verify-disabled
    )


def fix_rule() -> SimpleNamespace:
    return SimpleNamespace(
        rule_id="fix-verify",
        is_secret=False,
        fix_pattern=re.compile(r"verify\s*=\s*False"),
        fix_replacement="verify=True",
    )


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.notes: list[dict] = []

    def __call__(self, method: str, path: str, payload: dict | None):
        self.calls.append((method, path, payload))
        if method == "GET" and path.endswith("/notes?per_page=100"):
            return list(self.notes)
        if method == "GET" and path.endswith("/versions"):
            return [
                {
                    "base_sha": "base",
                    "start_sha": "start",
                    "head_sha": "head",
                }
            ]
        if method == "POST" and path.endswith("/notes"):
            note = {"id": 1, "body": (payload or {}).get("body", "")}
            self.notes.append(note)
            return note
        if method == "PUT":
            return {"id": 1}
        if method == "POST" and path.endswith("/discussions"):
            return {"id": "discussion"}
        return {}


class GitLabSummaryTests(unittest.TestCase):
    def test_summary_omits_flagged_code(self) -> None:
        body = build_gitlab_summary([finding()], block_threshold="high")
        self.assertIn(SUMMARY_MARKER, body)
        self.assertIn("fix-verify", body)
        self.assertNotIn("requests.get", body)

    def test_summary_note_is_created_then_updated(self) -> None:
        transport = FakeTransport()
        client = GitLabClient("token", transport=transport)
        options = GitLabOptions(project_id="42", merge_request_iid=7)
        created = publish_gitlab_summary(
            client, options, f"{SUMMARY_MARKER}\nfirst"
        )
        self.assertEqual(created.posted, 1)
        updated = publish_gitlab_summary(
            client, options, f"{SUMMARY_MARKER}\nsecond"
        )
        self.assertEqual(updated.updated, 1)
        methods = [method for method, _path, _payload in transport.calls]
        self.assertIn("POST", methods)
        self.assertIn("PUT", methods)

    def test_inline_suggestions_build_gitlab_positions(self) -> None:
        transport = FakeTransport()
        client = GitLabClient("token", transport=transport)
        options = GitLabOptions(
            project_id="42",
            merge_request_iid=7,
            commit_sha="head",
            diff_base_sha="base",
            start_sha="start",
        )
        suggestions = build_gitlab_inline_suggestions([finding()], [fix_rule()])
        self.assertEqual(len(suggestions), 1)
        result = publish_gitlab_inline_suggestions(client, options, suggestions)
        self.assertEqual(result.posted, 1)
        call = next(
            item for item in transport.calls if item[1].endswith("/discussions")
        )
        position = (call[2] or {})["position"]
        self.assertEqual(position["new_path"], "app.py")
        self.assertEqual(position["new_line"], 3)
        self.assertEqual(position["head_sha"], "head")

    def test_environment_defaults(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CI_API_V4_URL": "https://gitlab.example/api/v4",
                "CI_PROJECT_ID": "99",
                "CI_MERGE_REQUEST_IID": "12",
                "GITLAB_TOKEN": "secret",
                "CI_COMMIT_SHA": "head",
            },
            clear=True,
        ):
            options = gitlab_options_from_environment()
        self.assertEqual(options.project_id, "99")
        self.assertEqual(options.merge_request_iid, 12)
        self.assertEqual(options.base_url, "https://gitlab.example/api/v4")
        self.assertEqual(options.token, "secret")


if __name__ == "__main__":
    unittest.main()
