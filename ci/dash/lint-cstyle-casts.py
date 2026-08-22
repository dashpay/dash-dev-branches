#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Support C-style cast linting in Dash-specific C++ code."""

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import TextIO


CPP_SOURCE_EXTENSIONS = {".cc", ".cpp", ".cxx"}
DIAGNOSTIC_RE = re.compile(r"^(.*?):\d+:\d+: (?:warning|error): .*")
MACRO_EXPANSION_RE = re.compile(r"^(.*?):\d+:\d+: note: expanded from macro .*")
OLD_STYLE_CAST_DIAGNOSTICS = {"clang-diagnostic-old-style-cast", "google-readability-casting"}


def get_dash_files(source_root: Path) -> list[str]:
    manifest = source_root / "test/util/data/non-backported.txt"
    patterns = [line.strip() for line in manifest.read_text(encoding="utf8").splitlines() if line.strip()]
    result = subprocess.run(
        ["git", "ls-files", "--", *patterns],
        cwd=source_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf8",
    )
    return [line for line in result.stdout.splitlines() if line]


def is_dash_file(path: str, dash_files: set[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized == dash_file or normalized.endswith(f"/{dash_file}") for dash_file in dash_files)


def prepare_compile_database(source_root: Path, input_path: Path, output_dir: Path) -> None:
    database = json.loads(input_path.read_text(encoding="utf8"))

    for entry in database:
        if "arguments" not in entry:
            entry["arguments"] = shlex.split(entry.pop("command"))
        entry["arguments"].extend(["-Wold-style-cast", "-Wno-error=old-style-cast"])

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "compile_commands.json").write_text(json.dumps(database), encoding="utf8")


def filter_diagnostics(source_root: Path, input_stream: TextIO, output_stream: TextIO) -> bool:
    dash_files = set(get_dash_files(source_root))
    group: list[str] = []
    found_violation = False

    def flush() -> None:
        nonlocal found_violation
        if not group:
            return
        diagnostic_match = DIAGNOSTIC_RE.match(group[0])
        is_cast_diagnostic = any(diag in group[0] for diag in OLD_STYLE_CAST_DIAGNOSTICS)
        macro_expansions = [
            expansion_match
            for line in group
            if (expansion_match := MACRO_EXPANSION_RE.match(line))
        ]
        target_file = macro_expansions[-1].group(1) if macro_expansions else (diagnostic_match.group(1) if diagnostic_match else "")
        is_dash_diagnostic = is_dash_file(target_file, dash_files) if target_file else False

        if not is_cast_diagnostic or is_dash_diagnostic:
            output_stream.writelines(group)
        found_violation |= is_cast_diagnostic and is_dash_diagnostic
        group.clear()

    for line in input_stream:
        if DIAGNOSTIC_RE.match(line):
            flush()
            group.append(line)
        elif group:
            group.append(line)
        else:
            output_stream.write(line)
    flush()
    return found_violation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="create a Dash-aware compilation database")
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--source-root", type=Path, required=True)

    filter_parser = subparsers.add_parser("filter", help="filter clang-tidy diagnostics")
    filter_parser.add_argument("--source-root", type=Path, required=True)

    args = parser.parse_args()
    source_root = args.source_root.resolve()
    if args.command == "prepare":
        prepare_compile_database(source_root, args.input.resolve(), args.output_dir.resolve())
        return 0
    return int(filter_diagnostics(source_root, sys.stdin, sys.stdout))


if __name__ == "__main__":
    raise SystemExit(main())
