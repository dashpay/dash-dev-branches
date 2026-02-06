#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


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
    repo_root = (script_dir / "../..").resolve()

    makefile_path = repo_root / "depends/packages/native_cxxbridge.mk"
    if not makefile_path.exists():
        print(f"Error: {makefile_path} not found", file=sys.stderr)
        return 1

    version = get_version(makefile_path)
    print(f"cxx version: {version}")

    # Download tarball and compute hash
    sources_dir = repo_root / "depends/sources"
    stamps_dir = sources_dir / "download-stamps"
    file_name = f"native_cxxbridge-{version}.tar.gz"
    tarball_path = sources_dir / file_name
    url = f"https://github.com/dtolnay/cxx/archive/refs/tags/{version}.tar.gz"

    hash_value = download_and_hash(url, tarball_path)
    print(f"sha256: {hash_value}")

    # Update hash in makefile
    update_hash_in_file(makefile_path, "sha256_hash", hash_value)
    print(f"Updated sha256_hash in {makefile_path.name}")

    # Write stamp
    write_stamp(stamps_dir, "native_cxxbridge", version, hash_value, file_name)
    print(f"Wrote stamp for {file_name}")

    # Generate Cargo.lock
    toolchain_path = repo_root / "rust-toolchain.toml"
    if not toolchain_path.exists():
        print(f"Error: {toolchain_path} not found", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        print(f"Working in {tmp_path}")

        # Copy rust-toolchain.toml
        shutil.copy(toolchain_path, tmp_path / "rust-toolchain.toml")

        # Extract tarball
        print(f"Extracting {tarball_path}")
        with tarfile.open(tarball_path, "r:gz") as tar:
            tmp_path_real = os.path.realpath(tmp_path)
            for member in tar.getmembers():
                member_dest = os.path.join(tmp_path, member.name)
                if not os.path.realpath(member_dest).startswith(tmp_path_real + os.sep):
                    print(f"Error: Path traversal detected in tarball '{member.name}'")
                    return 1
                tar.extract(member, tmp_path)

        cxx_dir = tmp_path / f"cxx-{version}"
        if not cxx_dir.exists():
            print(f"Error: Expected directory {cxx_dir} not found after extraction", file=sys.stderr)
            return 1

        # Copy rust-toolchain.toml into cxx directory
        shutil.copy(toolchain_path, cxx_dir / "rust-toolchain.toml")

        # Run 'cargo check'
        print("Running cargo check --release --package=cxxbridge-cmd --bin=cxxbridge")
        result = subprocess.run(
            ["cargo", "check", "--release", "--package=cxxbridge-cmd", "--bin=cxxbridge"],
            cwd=cxx_dir,
        )
        if result.returncode != 0:
            print("Error: cargo check failed", file=sys.stderr)
            return 1

        # Copy Cargo.lock to patches directory
        cargo_lock_src = cxx_dir / "Cargo.lock"
        cargo_lock_dst = repo_root / "depends/patches/native_cxxbridge/Cargo.lock"
        if not cargo_lock_src.exists():
            print(f"Error: {cargo_lock_src} not found after cargo check", file=sys.stderr)
            return 1

        cargo_lock_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(cargo_lock_src, cargo_lock_dst)
        print(f"Copied Cargo.lock to {cargo_lock_dst}")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
