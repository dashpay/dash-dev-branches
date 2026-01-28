#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Zcash developers
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import re
import sys
import urllib.request
from pathlib import Path


# Corresponds to 'hosts/*.mk'
CROSS_TARGETS = [
    # FreeBSD
    "x86_64-unknown-freebsd",
    # Linux
    "aarch64-unknown-linux-musl",
    "armv7-unknown-linux-musleabihf",
    "powerpc64le-unknown-linux-musl",
    "riscv64gc-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
    # Windows
    "x86_64-pc-windows-gnu",
    # macOS
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
]


# Corresponds to 'builders/*.mk'
NATIVE_TARGETS = [
    # FreeBSD
    ("x86_64-unknown-freebsd", "x86_64_freebsd"),
    # Linux
    ("aarch64-unknown-linux-gnu", "aarch64_linux"),
    ("x86_64-unknown-linux-gnu", "x86_64_linux"),
    # macOS
    ("aarch64-apple-darwin", "aarch64_darwin"),
    ("x86_64-apple-darwin", "x86_64_darwin"),
]


def get_version(makefile_path: Path) -> str:
    content = makefile_path.read_text()
    match = re.search(r"\$\(package\)_version:=(.+)", content)
    if not match:
        raise RuntimeError(f"Could not find version in {makefile_path.name}")
    return match.group(1).strip()


def download_and_hash(url: str, dest: Path) -> str:
    hasher = hashlib.sha256()
    if dest.exists():
        print(f"  Using existing {dest.name}")
        with open(dest, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    print(f"  Downloading {dest.name}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response:
        with open(dest, "wb") as f:
            while chunk := response.read(8192):
                hasher.update(chunk)
                f.write(chunk)
    return hasher.hexdigest()


def write_stamp(stamps_dir: Path, pkg: str, version: str, sha256: str, file_name: str) -> None:
    stamps_dir.mkdir(parents=True, exist_ok=True)
    stamp_path = stamps_dir / f".stamp_fetched-{pkg}-{version}-{sha256}.hash"
    stamp_path.write_text(f"{sha256}  {file_name}\n")


def update_hash_in_file(makefile_path: Path, pattern: str, new_hash: str) -> None:
    content = makefile_path.read_text()
    regex = re.compile(rf"^(\$\(package\)_{pattern}:=).*$", re.MULTILINE)
    if not regex.search(content):
        raise RuntimeError(f"Could not find {pattern} in {makefile_path.name}")
    new_content = regex.sub(rf"\g<1>{new_hash}", content)
    makefile_path.write_text(new_content)


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    depends_dir = (script_dir / "../../depends").resolve()
    native_rust_path = depends_dir / "packages/native_rust.mk"
    rust_stdlib_path = depends_dir / "packages/rust_stdlib.mk"
    sources_dir = depends_dir / "sources"
    stamps_dir = sources_dir / "download-stamps"

    if not native_rust_path.exists():
        print(f"Error: {native_rust_path} not found", file=sys.stderr)
        return 1

    if not rust_stdlib_path.exists():
        print(f"Error: {rust_stdlib_path} not found", file=sys.stderr)
        return 1

    rust_version = get_version(native_rust_path)

    print(f"Rust version: {rust_version}\n")
    print("Updating native compiler hashes:")

    for rust_target, makefile_id in NATIVE_TARGETS:
        file_name = f"rust-{rust_version}-{rust_target}.tar.gz"
        url = f"https://static.rust-lang.org/dist/{file_name}"
        hash_value = download_and_hash(url, sources_dir / file_name)
        update_hash_in_file(native_rust_path, f"sha256_hash_{makefile_id}", hash_value)
        write_stamp(stamps_dir, "native_rust", rust_version, hash_value, file_name)
        print(f"  Updated sha256_hash_{makefile_id}")

    print("\nUpdating stdlib hashes:")
    for rust_target in CROSS_TARGETS:
        file_name = f"rust-std-{rust_version}-{rust_target}.tar.gz"
        url = f"https://static.rust-lang.org/dist/{file_name}"
        hash_value = download_and_hash(url, sources_dir / file_name)
        update_hash_in_file(rust_stdlib_path, f"sha256_hash_{rust_target}", hash_value)
        write_stamp(stamps_dir, "rust_stdlib", rust_version, hash_value, file_name)
        print(f"  Updated sha256_hash_{rust_target}")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
