#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import atexit
import os
import shutil
import subprocess
import sys

PY_NAME = os.path.basename(sys.argv[0])
ROOT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..'))

CARGO_DIR = os.path.join(ROOT_DIR, '.cargo')
CARGO_CONFIG = os.path.join(CARGO_DIR, 'config.toml')
CARGO_CONFIG_BAK = CARGO_CONFIG + '.bak'
CARGO_LOCK = os.path.join(ROOT_DIR, 'Cargo.lock')

def main():
    if not shutil.which('cargo'):
        print(f'{PY_NAME}: cargo not found in PATH', file=sys.stderr)
        return 1

    had_config = os.path.exists(CARGO_CONFIG)
    cargo_lock_bak = None

    if had_config:
        shutil.copy2(CARGO_CONFIG, CARGO_CONFIG_BAK)
        os.remove(CARGO_CONFIG)
        atexit.register(lambda: shutil.move(CARGO_CONFIG_BAK, CARGO_CONFIG) if os.path.exists(CARGO_CONFIG_BAK) else None)

    if os.path.exists(CARGO_LOCK):
        cargo_lock_bak = CARGO_LOCK + '.bak'
        shutil.copy2(CARGO_LOCK, cargo_lock_bak)

    try:
        subprocess.check_call(['cargo', 'generate-lockfile'], cwd=ROOT_DIR)
    except Exception:
        if cargo_lock_bak:
            shutil.move(cargo_lock_bak, CARGO_LOCK)
        raise
    finally:
        if had_config:
            shutil.move(CARGO_CONFIG_BAK, CARGO_CONFIG)

    if cargo_lock_bak and os.path.exists(cargo_lock_bak):
        os.remove(cargo_lock_bak)

    return 0


if __name__ == '__main__':
    sys.exit(main())
