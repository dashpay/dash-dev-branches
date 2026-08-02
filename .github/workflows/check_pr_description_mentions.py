#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Reject GitHub @username mentions in pull request descriptions.

Mentions are copied into merge commits and re-notify people on merge,
rebase, or backport. Email addresses are allowed; empty descriptions pass.

Usage:
    PR_BODY='...' python3 .github/workflows/check_pr_description_mentions.py
    python3 .github/workflows/check_pr_description_mentions.py --body-file path
    printf '%s' '...' | python3 .github/workflows/check_pr_description_mentions.py --stdin
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Optional, Sequence, Tuple


# Match complete, conventional dot-atom email addresses with a dotted domain.
# Email spans are excluded from the independent GitHub @username scan below.
EMAIL_LOCAL_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
EMAIL_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_RE = re.compile(
    rf"{EMAIL_LOCAL_ATOM}(?:\.{EMAIL_LOCAL_ATOM})*"
    rf"@{EMAIL_DOMAIN_LABEL}(?:\.{EMAIL_DOMAIN_LABEL})+"
)
EMAIL_LOCAL_SPECIALS = frozenset("!#$%&'*+/=?^_`{|}~-")

# GitHub @username: @ + 1-39 characters (alphanumeric or internal hyphens).
MENTION_RE = re.compile(r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\b")

ERROR_MESSAGE = """\
::error::PR description contains GitHub @mentions.
Do not put @username mentions in PR descriptions.
They are copied into merge commits and notify people again
whenever the PR is merged, rebased, or backported.
Refer to people by name or GitHub URL without the leading @.\
"""


def find_email_spans(line: str) -> List[Tuple[int, int]]:
    """Return spans for complete email addresses in a line."""
    spans: List[Tuple[int, int]] = []
    for match in EMAIL_RE.finditer(line):
        start, end = match.span()
        if start > 0:
            previous = line[start - 1]
            if previous.isalnum() or previous == "." or previous in EMAIL_LOCAL_SPECIALS:
                continue
        if end < len(line) and (
            line[end].isalnum() or line[end] in "-_"
        ):
            continue
        spans.append((start, end))
    return spans


def find_mentions(body: str) -> List[Tuple[int, str, str]]:
    """Return (1-based line number, line text, match text) for each @mention."""
    matches: List[Tuple[int, str, str]] = []
    for line_no, line in enumerate(body.splitlines(), start=1):
        email_spans = find_email_spans(line)
        for match in MENTION_RE.finditer(line):
            if any(start <= match.start() < end for start, end in email_spans):
                continue
            matches.append((line_no, line, match.group(0)))
    return matches


def check_body(body: Optional[str]) -> int:
    """Validate PR body. Return 0 on pass, 1 when @mentions are present."""
    if body is None or body == "":
        print("PR description is empty; no @mentions to check.")
        return 0

    matches = find_mentions(body)
    if not matches:
        print("No @mentions found in PR description.")
        return 0

    for line_no, line, mention in matches:
        print(f"{line_no}:{mention}: {line}")

    print("", file=sys.stderr)
    print(ERROR_MESSAGE, file=sys.stderr)
    return 1


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject GitHub @username mentions in pull request descriptions."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--body-file",
        metavar="PATH",
        help="Read the PR body from PATH instead of the PR_BODY environment variable",
    )
    source.add_argument(
        "--stdin",
        action="store_true",
        help="Read the PR body from stdin instead of the PR_BODY environment variable",
    )
    return parser.parse_args(argv)


def read_body(args: argparse.Namespace) -> Optional[str]:
    if args.body_file is not None:
        with open(args.body_file, encoding="utf-8") as handle:
            return handle.read()
    if args.stdin:
        return sys.stdin.read()
    # PR_BODY may be unset (treated as empty) or set to "" / multi-line text.
    # Never shell-interpolate untrusted body content; workflows pass it via env.
    if "PR_BODY" not in os.environ:
        return None
    return os.environ["PR_BODY"]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        body = read_body(args)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: failed to read PR body: {exc}", file=sys.stderr)
        return 1
    return check_body(body)


if __name__ == "__main__":
    raise SystemExit(main())
