# Dash Core Agent Guide

This file is for automated coding agents working in Dash Core. Keep it
practical: prefer local source, tests, and project history over guesses.

`AGENTS.md` and `CLAUDE.md` intentionally contain the same guidance. When one
changes, update the other in the same commit.

## First Principles

- Understand the code path before editing. Read callers, callees, tests, and
  recent history for the touched files.
- Keep changes narrow. Do not mix cleanup, formatting, refactors, and behavior
  changes unless the task explicitly asks for it.
- Preserve Dash-specific behavior when backporting or refactoring Bitcoin Core
  code. Dash consensus, masternodes, LLMQs, ChainLocks, InstantSend, Platform
  credit-pool logic, governance, and sporks often extend the upstream path.
- Do not add symlinks. `contrib/devtools/github-merge.py` rejects symlinks in
  the tree during merge.
- Do not edit generated release artifacts, Guix/release files, vendored code, or
  translations unless the task is specifically about those files.

## Repository Map

- `src/` - C++ implementation.
- `src/bench/` - benchmarks.
- `src/index/`, `src/interfaces/`, `src/node/`, `src/rpc/`, `src/wallet/` -
  subsystem code inherited mostly from Bitcoin Core.
- `src/llmq/`, `src/masternode/`, `src/evo/`, `src/governance/`,
  `src/coinjoin/`, `src/instantsend/`, `src/spork*` - Dash-specific systems.
- `src/test/`, `src/wallet/test/`, `src/qt/test/` - C++ unit tests.
- `test/functional/` - Python functional tests for `dashd` and `dash-qt`.
- `test/lint/` - static checks.
- `depends/` - dependency build system.
- `ci/`, `.github/` - CI entry points and GitHub workflows.
- `doc/` - user and developer documentation.
- `contrib/` - scripts and release/maintenance tooling.

Vendored or subtree-style code should normally be left alone:

- `src/{crc32c,dashbls,gsl,immer,leveldb,minisketch,secp256k1,univalue}`
- `src/crypto/{ctaes,x11}`

`test/util/data/non-backported.txt` lists Dash-specific files used by Dash
style/lint checks such as clang-format-diff and cppcheck. Do not treat it as a
list of skipped upstream backport hunks.

## Build Commands

Use portable parallelism in examples. Linux-only CPU-count helpers are not
available on every supported developer host.

```bash
./autogen.sh

JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
JOBS="$(( JOBS > 1 ? JOBS - 1 : 1 ))"

make -C depends -j"$JOBS"

# Use the depends prefix printed for your platform, for example
# depends/x86_64-pc-linux-gnu or depends/aarch64-apple-darwin24.3.0.
./configure --prefix="$(pwd)/depends/[platform-triplet]"

make -j"$JOBS"
```

Useful developer configure flags:

```bash
./configure --prefix="$(pwd)/depends/[platform-triplet]" \
            --disable-hardening \
            --enable-crash-hooks \
            --enable-debug \
            --enable-reduce-exports \
            --enable-stacktraces \
            --enable-suppress-external-warnings \
            --enable-werror
```

Generate `compile_commands.json`:

```bash
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
JOBS="$(( JOBS > 1 ? JOBS - 1 : 1 ))"
bear -- make -j"$JOBS"
```

When adding, removing, or renaming C++ source files, update the build system in
the same change. Most source/test files need `src/Makefile.am` or
`src/Makefile.test.include` updates, and some backports also require matching
CI/lint list changes.

## Test Commands

Choose tests based on the files touched. Do not claim broad validation if only a
targeted test was run.

```bash
# All unit tests
make check

# One Boost test suite or case
./src/test/test_dash --run_test=getarg_tests

# All functional tests
test/functional/test_runner.py

# One functional test
test/functional/test_runner.py wallet_hd.py

# Parallel functional tests
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
test/functional/test_runner.py -j"$JOBS"

# Lint
test/lint/all-lint.py
test/lint/lint-python.py
test/lint/lint-shell.py
test/lint/lint-whitespace.py
test/lint/lint-circular-dependencies.py
```

Functional-test prerequisites and usage details live in `test/README.md`.
Several Dash-specific tests need the `dash_hash` Python package.

## Backport Work

Dash Core regularly backports Bitcoin Core changes. Treat backports as
source-history work, not only conflict resolution.

- Identify the exact upstream Bitcoin Core PR(s) and commit(s).
- Keep upstream backport commits as close to 1:1 as practical. Put shared Dash
  repair work on a staging/base branch instead of hiding it inside an unrelated
  upstream backport commit.
- Compare the upstream diff to the Dash diff file by file.
- Check prerequisite PRs. If an upstream hunk depends on a helper, test, type,
  or file introduced by an earlier Bitcoin PR, either backport the prerequisite
  or document why the hunk is intentionally excluded.
- Do not silently drop upstream tests. If a test depends on a missing
  prerequisite, call that out in the PR description or add the prerequisite.
- If a backport is partial, explain the omitted upstream commits, hunks, or
  tests in the commit or PR text.
- Verify the PR title/body matches the actual commits still reachable from the
  branch. Stale "backports X" metadata has caused bad reviews.
- Keep Dash adaptations explicit. When upstream code touches a path that Dash
  has extended, inspect the Dash-specific logic before accepting the upstream
  shape.
- Resolve conflicts against Dash APIs, not only upstream structure. A backport
  that textually resembles Bitcoin Core can still fail to compile or lose Dash
  behavior if Dash-only overloads, helpers, or wallet paths are removed.

## Dash-Specific Review Hotspots

Be extra careful around:

- consensus and script flags;
- special transaction payload serialization;
- deterministic masternode list updates;
- LLMQ DKG, signing sessions, recovered signatures, and quorum rotation;
- InstantSend and ChainLocks request/relay paths;
- governance object and superblock payment logic;
- EvoDB, credit-pool, asset-lock, and Platform integration code;
- network-message serialization, checksums, and partial-send paths;
- BLS scheme transitions across connect, disconnect, undo, and activation
  boundaries;
- future DKG/quorum prediction, which must evaluate quorum availability at the
  relevant future work/cycle base instead of only the current tip;
- time, mocktime, scheduler, and interrupt/shutdown behavior.

For these areas, prefer small tests that prove the invariant being changed.

## PR Hygiene

- Use atomic commits. Each commit should build and make sense on its own.
- PR titles follow Conventional Commits, including `backport:` for Bitcoin Core
  backports.
- PR descriptions must follow `.github/PULL_REQUEST_TEMPLATE.md`: remove the
  italicized helper prompts, fill in the required sections, and keep the
  checklist accurate for the change.
- Do not put `@` mentions in PR descriptions; they are copied into merge
  commits and notify users repeatedly.
- Explain what changed and why. For bug fixes, include the failure mode and why
  the chosen fix is correct.
- If CI fails for reasons unrelated to the PR, document the evidence instead of
  pushing empty commits or unrelated changes.
- For depends/cache failures, inspect both the cache-producing and
  cache-consuming jobs. Rerunning only the failed consumer can preserve the same
  missing-cache failure.

## Local Debugging

```bash
# Run dashd with broad logging
./src/dashd -debug=all -printtoconsole

# Run a functional test against a custom binary
test/functional/test_runner.py --dashd=/path/to/dashd wallet_hd.py

# Keep failed functional-test datadirs
test/functional/test_runner.py --nocleanup --tracerpc -l DEBUG wallet_hd.py

# Debug a unit-test binary
gdb ./src/test/test_dash

# Profile a functional test
test/functional/test_runner.py --perf wallet_hd.py
perf report -i /path/to/datadir/test.perf.data --stdio | c++filt
```

## When In Doubt

- Read `CONTRIBUTING.md`, `doc/developer-notes.md`, and nearby tests.
- Search for similar code with `rg` before inventing a new pattern.
- Prefer established project helpers over ad hoc parsing or shell tricks.
- Leave a clear note in the PR when a choice is deliberate and could otherwise
  look like an omission.
