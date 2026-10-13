#!/usr/bin/env python3
"""Verify a signature-preserving Stash 4.3.2 (561) activation test copy."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import activate_stash_561 as activation


class VerificationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(root: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = ("symlink", os.readlink(path))
        elif path.is_file():
            result[relative] = ("file", sha256(path))
        elif path.is_dir():
            result[relative] = ("directory", "")
        else:
            result[relative] = ("other", "")
    return result


def check_preferences() -> None:
    for key in ("SUEnableAutomaticChecks", "SUAutomaticallyUpdate"):
        proc = subprocess.run(
            ["/usr/bin/defaults", "read", activation.APP_ID, key],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or proc.stdout.strip() not in {"0", "false", "FALSE"}:
            raise VerificationError(f"automatic-update preference is not disabled: {key}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=activation.DEFAULT_INPUT)
    parser.add_argument("--app", type=Path, default=activation.DEFAULT_OUTPUT)
    parser.add_argument("--skip-preferences", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source.expanduser().resolve(strict=True)
    app = args.app.expanduser().resolve(strict=True)
    activation.self_test()
    activation.validate_app(source)
    activation.validate_app(app)
    source_inventory = inventory(source)
    app_inventory = inventory(app)
    if source_inventory != app_inventory:
        missing = sorted(set(source_inventory).difference(app_inventory))
        extra = sorted(set(app_inventory).difference(source_inventory))
        changed = sorted(
            path
            for path in set(source_inventory).intersection(app_inventory)
            if source_inventory[path] != app_inventory[path]
        )
        raise VerificationError(
            f"bundle differs from signed source: missing={missing[:5]}, extra={extra[:5]}, changed={changed[:5]}"
        )
    if not args.skip_preferences:
        check_preferences()
    print(f"[+] source and output bundles are byte-identical ({len(source_inventory)} entries)")
    print(f"[+] Developer ID TeamIdentifier: {activation.TEAM_ID}")
    print("[+] restricted system-extension and network-extension entitlements preserved")
    if args.skip_preferences:
        print("[+] automatic-update preferences: skipped")
    else:
        print("[+] automatic-update preferences: disabled for the current user")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (activation.ActivationError, VerificationError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
