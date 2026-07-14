#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import importlib.util
from pathlib import Path
import argparse
import requests
import sys
import unittest


SCRIPT_PATH = Path(__file__).with_name("handle_potential_conflicts.py")
SPEC = importlib.util.spec_from_file_location("handle_potential_conflicts", SCRIPT_PATH)
handle_potential_conflicts = importlib.util.module_from_spec(SPEC)
sys.modules["handle_potential_conflicts"] = handle_potential_conflicts
SPEC.loader.exec_module(handle_potential_conflicts)


BOT_USER = {"login": "github-actions[bot]", "type": "Bot"}
USER = {"login": "contributor", "type": "User"}


def comment(comment_id, body, user=None):
    return {
        "id": comment_id,
        "body": body,
        "user": user or BOT_USER,
    }


class TestPotentialConflictComments(unittest.TestCase):
    def test_extract_state_from_managed_comment(self):
        body = handle_potential_conflicts.render_comment_body({
            "outbound": [
                {"number": 2, "title": "two", "url": "https://example.test/2", "files": []},
            ],
            "inbound": {
                "3": {"number": 3, "title": "three", "url": "https://example.test/3", "files": ["src/a.cpp"]},
            },
        })

        state = handle_potential_conflicts.extract_state(body)

        self.assertEqual(2, state["outbound"][0]["number"])
        self.assertEqual(3, state["inbound"]["3"]["number"])

    def test_invalid_state_is_treated_as_empty(self):
        body = """<!-- dash-potential-conflicts:v1
not-json
-->
## Potential PR merge conflicts
"""

        state = handle_potential_conflicts.extract_state(body)

        self.assertEqual([], state["outbound"])
        self.assertEqual({}, state["inbound"])

    def test_render_comment_body_has_one_marker_and_both_sections(self):
        state = {
            "outbound": [
                {
                    "number": 12,
                    "title": "fix: target",
                    "url": "https://github.com/dashpay/dash/pull/12",
                    "files": ["src/net.cpp"],
                }
            ],
            "inbound": {
                "9": {
                    "number": 9,
                    "title": "refactor: source",
                    "url": "https://github.com/dashpay/dash/pull/9",
                    "files": ["src/net.cpp"],
                }
            },
        }

        body = handle_potential_conflicts.render_comment_body(state)

        self.assertEqual(1, body.count("dash-potential-conflicts:v1"))
        self.assertIn("If this PR merges first", body)
        self.assertIn("If these PRs merge first", body)
        self.assertIn("[#12: fix: target](https://github.com/dashpay/dash/pull/12)", body)
        self.assertIn("[#9: refactor: source](https://github.com/dashpay/dash/pull/9)", body)

    def test_rendered_comment_state_round_trips(self):
        state = {
            "outbound": [
                {
                    "number": 12,
                    "title": f"title with {handle_potential_conflicts.COMMENT_START} --> marker-like text",
                    "url": "https://github.com/dashpay/dash/pull/12",
                    "files": ["src/net.cpp"],
                }
            ],
            "inbound": {},
        }

        body = handle_potential_conflicts.render_comment_body(state)
        extracted = handle_potential_conflicts.extract_state(body)

        self.assertEqual(state, extracted)
        self.assertTrue(body.startswith("## Potential PR merge conflicts"))
        self.assertTrue(body.rstrip("\n").endswith(handle_potential_conflicts.COMMENT_END))

    def test_extract_state_from_legacy_marker_first_comment(self):
        state = {
            "outbound": [
                {"number": 2, "title": "two", "url": "https://example.test/2", "files": []},
            ],
            "inbound": {},
        }
        body = handle_potential_conflicts.render_comment_body(state)
        marker_index = body.rfind(handle_potential_conflicts.COMMENT_START)
        legacy_body = body[marker_index:] + body[:marker_index]

        self.assertTrue(legacy_body.startswith(handle_potential_conflicts.COMMENT_START))
        self.assertEqual(state, handle_potential_conflicts.extract_state(legacy_body))

    def test_rendered_comment_escapes_markdown_content(self):
        body = handle_potential_conflicts.render_comment_body({
            "outbound": [
                {
                    "number": 12,
                    "title": "fix [link] title",
                    "url": "https://github.com/dashpay/dash/pull/12",
                    "files": ["src/`odd`.cpp"],
                },
            ],
            "inbound": {},
        })

        self.assertIn(r"[#12: fix \[link\] title](https://github.com/dashpay/dash/pull/12)", body)
        self.assertIn("<code>src/`odd`.cpp</code>", body)

    def test_normalize_state_filters_malformed_entries(self):
        state = handle_potential_conflicts.normalize_state({
            "outbound": [
                {"number": "12", "title": "valid", "url": "https://example.test/12", "files": ["src/a.cpp"]},
                {"title": "missing number"},
                "not-a-dict",
            ],
            "inbound": {
                "bad": {"title": "missing number"},
                "13": {"number": "13", "title": "valid inbound", "url": "https://example.test/13", "files": []},
            },
        })

        self.assertEqual([12], [item["number"] for item in state["outbound"]])
        self.assertEqual(["13"], list(state["inbound"].keys()))

    def test_state_is_empty_only_when_both_directions_are_empty(self):
        self.assertTrue(handle_potential_conflicts.state_is_empty({"outbound": [], "inbound": {}}))
        self.assertFalse(handle_potential_conflicts.state_is_empty({"outbound": [{"number": 1}], "inbound": {}}))
        self.assertFalse(handle_potential_conflicts.state_is_empty({"outbound": [], "inbound": {"2": {"number": 2}}}))

    def test_user_forged_managed_comment_is_ignored(self):
        body = handle_potential_conflicts.render_comment_body({
            "outbound": [{"number": 12, "title": "forged", "url": "https://example.test/12", "files": []}],
            "inbound": {},
        })
        comments = [comment(123, body, USER)]
        original_list_issue_comments = handle_potential_conflicts.list_issue_comments
        handle_potential_conflicts.list_issue_comments = lambda pr_num: comments
        try:
            managed_comments = handle_potential_conflicts.find_managed_comments(1)
        finally:
            handle_potential_conflicts.list_issue_comments = original_list_issue_comments

        self.assertEqual([], managed_comments)

    def test_update_comments_replaces_reciprocal_entries(self):
        our_pr_json = {
            "number": 10,
            "title": "fix: source",
            "html_url": "https://github.com/dashpay/dash/pull/10",
        }
        validated_conflicts = [
            {
                "number": 12,
                "title": "fix: new target",
                "url": "https://github.com/dashpay/dash/pull/12",
                "files": ["src/net.cpp"],
            }
        ]
        comments = {
            10: handle_potential_conflicts.ManagedComment(
                comment_id=1,
                body="",
                state={
                    "outbound": [
                        {
                            "number": 11,
                            "title": "fix: stale target",
                            "url": "https://github.com/dashpay/dash/pull/11",
                            "files": ["src/old.cpp"],
                        }
                    ],
                    "inbound": {
                        "8": {
                            "number": 8,
                            "title": "fix: incoming",
                            "url": "https://github.com/dashpay/dash/pull/8",
                            "files": ["src/in.cpp"],
                        }
                    },
                },
            ),
            11: handle_potential_conflicts.ManagedComment(comment_id=2, body="", state={"outbound": [], "inbound": {"10": {"number": 10}}}),
            12: handle_potential_conflicts.ManagedComment(comment_id=3, body="", state={"outbound": [], "inbound": {}}),
        }
        saved = {}
        original_get_managed_comment = handle_potential_conflicts.get_managed_comment
        original_save_managed_comment = handle_potential_conflicts.save_managed_comment
        handle_potential_conflicts.get_managed_comment = lambda pr_num: comments[pr_num]
        handle_potential_conflicts.save_managed_comment = lambda pr_num, state: saved.setdefault(pr_num, state)
        try:
            handle_potential_conflicts.update_comments(our_pr_json, validated_conflicts)
        finally:
            handle_potential_conflicts.get_managed_comment = original_get_managed_comment
            handle_potential_conflicts.save_managed_comment = original_save_managed_comment

        self.assertEqual([12], [item["number"] for item in saved[10]["outbound"]])
        self.assertIn("8", saved[10]["inbound"])
        self.assertNotIn("10", saved[11]["inbound"])
        self.assertEqual(10, saved[12]["inbound"]["10"]["number"])

    def test_cleanup_closed_pr_removes_bidirectional_state(self):
        comments = {
            10: handle_potential_conflicts.ManagedComment(
                comment_id=10,
                body="managed",
                state={
                    "outbound": [
                        {
                            "number": 12,
                            "title": "fix: target",
                            "url": "https://github.com/dashpay/dash/pull/12",
                            "files": ["src/net.cpp"],
                        }
                    ],
                    "inbound": {
                        "8": {
                            "number": 8,
                            "title": "fix: source",
                            "url": "https://github.com/dashpay/dash/pull/8",
                            "files": ["src/net.cpp"],
                        }
                    },
                },
            ),
            8: handle_potential_conflicts.ManagedComment(
                comment_id=8,
                body="managed",
                state={
                    "outbound": [
                        {"number": 10, "title": "fix: closed target", "url": "https://github.com/dashpay/dash/pull/10", "files": []},
                        {"number": 11, "title": "fix: other target", "url": "https://github.com/dashpay/dash/pull/11", "files": []},
                    ],
                    "inbound": {},
                },
            ),
            12: handle_potential_conflicts.ManagedComment(
                comment_id=12,
                body="managed",
                state={"outbound": [], "inbound": {"10": {"number": 10}}},
            ),
        }
        saved = {}
        deleted = []
        original_get_managed_comment = handle_potential_conflicts.get_managed_comment
        original_find_managed_comments = handle_potential_conflicts.find_managed_comments
        original_save_managed_comment = handle_potential_conflicts.save_managed_comment
        original_github_delete = handle_potential_conflicts.github_delete
        handle_potential_conflicts.get_managed_comment = lambda pr_num: comments[pr_num]
        handle_potential_conflicts.find_managed_comments = lambda pr_num: [comments[pr_num]]
        handle_potential_conflicts.save_managed_comment = lambda pr_num, state: saved.setdefault(pr_num, state)
        handle_potential_conflicts.github_delete = lambda path: deleted.append(path)
        try:
            handle_potential_conflicts.cleanup_closed_pr_comments(10)
        finally:
            handle_potential_conflicts.get_managed_comment = original_get_managed_comment
            handle_potential_conflicts.find_managed_comments = original_find_managed_comments
            handle_potential_conflicts.save_managed_comment = original_save_managed_comment
            handle_potential_conflicts.github_delete = original_github_delete

        self.assertEqual([11], [item["number"] for item in saved[8]["outbound"]])
        self.assertNotIn("10", saved[12]["inbound"])
        self.assertEqual(["issues/comments/10"], deleted)

    def test_comment_fetch_failure_prevents_comment_creation(self):
        posted = []
        original_list_issue_comments = handle_potential_conflicts.list_issue_comments
        original_github_post = handle_potential_conflicts.github_post
        handle_potential_conflicts.list_issue_comments = lambda pr_num: (_ for _ in ()).throw(requests.RequestException("boom"))
        handle_potential_conflicts.github_post = lambda path, payload: posted.append((path, payload))
        try:
            with self.assertRaises(requests.RequestException):
                handle_potential_conflicts.save_managed_comment(
                    10,
                    {
                        "outbound": [
                            {
                                "number": 12,
                                "title": "fix: target",
                                "url": "https://github.com/dashpay/dash/pull/12",
                                "files": [],
                            }
                        ],
                        "inbound": {},
                    },
                )
        finally:
            handle_potential_conflicts.list_issue_comments = original_list_issue_comments
            handle_potential_conflicts.github_post = original_github_post

        self.assertEqual([], posted)

    def test_main_cleans_current_draft_pr(self):
        cleaned = []
        original_parse_args = handle_potential_conflicts.parse_args
        original_get_pr_json = handle_potential_conflicts.get_pr_json
        original_cleanup_closed_pr_comments = handle_potential_conflicts.cleanup_closed_pr_comments
        handle_potential_conflicts.parse_args = lambda: argparse.Namespace(
            pr_number=10,
            dry_run=False,
            cleanup_closed=False,
        )
        handle_potential_conflicts.get_pr_json = lambda pr_num: {
            "number": pr_num,
            "draft": True,
            "head": {"label": "contributor:branch"},
        }
        handle_potential_conflicts.cleanup_closed_pr_comments = lambda pr_num: cleaned.append(pr_num)
        try:
            handle_potential_conflicts.main()
        finally:
            handle_potential_conflicts.parse_args = original_parse_args
            handle_potential_conflicts.get_pr_json = original_get_pr_json
            handle_potential_conflicts.cleanup_closed_pr_comments = original_cleanup_closed_pr_comments

        self.assertEqual([10], cleaned)

    def test_save_managed_comment_deletes_duplicate_managed_comments(self):
        comments = [
            comment(
                1,
                handle_potential_conflicts.render_comment_body({
                    "outbound": [{"number": 11, "title": "old", "url": "https://example.test/11", "files": []}],
                    "inbound": {},
                }),
            ),
            comment(
                3,
                handle_potential_conflicts.render_comment_body({
                    "outbound": [{"number": 12, "title": "old", "url": "https://example.test/12", "files": []}],
                    "inbound": {},
                }),
            ),
        ]
        patched = []
        deleted = []
        posted = []
        original_list_issue_comments = handle_potential_conflicts.list_issue_comments
        original_github_patch = handle_potential_conflicts.github_patch
        original_github_delete = handle_potential_conflicts.github_delete
        original_github_post = handle_potential_conflicts.github_post
        handle_potential_conflicts.list_issue_comments = lambda pr_num: comments
        handle_potential_conflicts.github_patch = lambda path, payload: patched.append((path, payload))
        handle_potential_conflicts.github_delete = lambda path: deleted.append(path)
        handle_potential_conflicts.github_post = lambda path, payload: posted.append((path, payload))
        try:
            handle_potential_conflicts.save_managed_comment(
                10,
                {
                    "outbound": [
                        {
                            "number": 13,
                            "title": "new",
                            "url": "https://example.test/13",
                            "files": [],
                        }
                    ],
                    "inbound": {},
                },
            )
        finally:
            handle_potential_conflicts.list_issue_comments = original_list_issue_comments
            handle_potential_conflicts.github_patch = original_github_patch
            handle_potential_conflicts.github_delete = original_github_delete
            handle_potential_conflicts.github_post = original_github_post

        self.assertEqual(["issues/comments/3"], [path for path, _payload in patched])
        self.assertEqual(["issues/comments/1"], deleted)
        self.assertEqual([], posted)

    def test_format_files_limits_long_file_lists(self):
        files = [f"src/file_{i}.cpp" for i in range(handle_potential_conflicts.MAX_FILE_DETAILS + 2)]

        formatted = handle_potential_conflicts.format_files(files)

        self.assertIn("and 2 more", formatted)
        self.assertIn("<code>src/file_0.cpp</code>", formatted)
        self.assertNotIn(f"<code>src/file_{handle_potential_conflicts.MAX_FILE_DETAILS}.cpp</code>", formatted)


if __name__ == "__main__":
    unittest.main()
