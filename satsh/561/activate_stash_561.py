#!/usr/bin/env python3
"""Create and activate a signature-preserving Stash 4.3.2 (561) test copy."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


APP_ID = "ws.stash.app.mac"
APP_VERSION = "4.3.2"
APP_BUILD = "561"
TEAM_ID = "B36787XSBG"
MAIN_SHA256 = "004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f"
HELPER_SHA256 = "91bd0c16aab9e1e5c36467d02f853d417a15a2c01bba2fadf741f05eaefa0430"
ACTIVATION_PLAINTEXT = bytes.fromhex("08b10418808080808040201e28023002381e")
AES_IV = b"ws.stash.key.aes"
KEYCHAIN_SERVICE = APP_ID
DEVICE_ACCOUNT = "stash-mac-device-id"
DEVICE_LABEL = f"{APP_ID}.device-id"
ACTIVATION_ACCOUNT = "stash-mac-activation-info-serialized"
ACTIVATION_LABEL = "activation-info"
KNOWN_TEST_CIPHER = bytes.fromhex(
    "71273c17dca50e4deaa297bddf14fbcc8d3cb902554cd5ae94c64c754a2b7b52"
)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = SCRIPT_DIR / "Stash 561.app"
DEFAULT_OUTPUT = SCRIPT_DIR / "Stash_561_patched.app"
FINGERPRINT_SOURCE = SCRIPT_DIR / "device_fingerprint.c"


class ActivationError(RuntimeError):
    pass


def run(
    argv: list[str | os.PathLike[str]],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = [str(arg) for arg in argv]
    proc = subprocess.run(command, input=input_bytes, capture_output=True, check=False)
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode(errors="replace").strip()
        raise ActivationError(f"command failed ({proc.returncode}): {' '.join(command)}\n{detail}")
    return proc


def run_secret(
    argv: list[str | os.PathLike[str]], *, secret_indexes: set[int]
) -> subprocess.CompletedProcess[bytes]:
    """Run a command while keeping secret argv values out of diagnostics."""
    command = [str(arg) for arg in argv]
    display = ["[REDACTED]" if index in secret_indexes else arg for index, arg in enumerate(command)]
    proc = subprocess.run(command, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode(errors="replace").strip()
        raise ActivationError(f"command failed ({proc.returncode}): {' '.join(display)}\n{detail}")
    return proc


def text_output(argv: list[str | os.PathLike[str]]) -> str:
    proc = run(argv)
    return (proc.stdout or proc.stderr).decode(errors="replace").strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_paths(app: Path) -> tuple[Path, Path, Path]:
    return (
        app / "Contents" / "Info.plist",
        app / "Contents" / "MacOS" / "Stash",
        app / "Contents" / "Library" / "LaunchServices" / "ws.stash.app.mac.daemon.helper",
    )


def codesign_fields(app: Path) -> dict[str, str]:
    proc = run(["/usr/bin/codesign", "-d", "--verbose=4", app])
    result: dict[str, str] = {}
    for line in (proc.stdout + proc.stderr).decode(errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    return result


def entitlements(app: Path) -> dict[str, object]:
    proc = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", app])
    payload = proc.stdout
    start = payload.find(b"<?xml")
    if start < 0:
        raise ActivationError("codesign did not return an XML entitlement plist")
    return plistlib.loads(payload[start:])


def validate_app(app: Path) -> None:
    if app.suffix != ".app" or not app.is_dir():
        raise ActivationError(f"input is not an app bundle: {app}")
    info_path, main_path, helper_path = bundle_paths(app)
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ActivationError(f"cannot read Info.plist: {exc}") from exc

    expected = {
        "CFBundleIdentifier": APP_ID,
        "CFBundleShortVersionString": APP_VERSION,
        "CFBundleVersion": APP_BUILD,
    }
    for key, value in expected.items():
        if info.get(key) != value:
            raise ActivationError(f"unexpected {key}: {info.get(key)!r}; expected {value!r}")
    if sha256(main_path) != MAIN_SHA256:
        raise ActivationError("main executable SHA-256 does not match the authorized build")
    if sha256(helper_path) != HELPER_SHA256:
        raise ActivationError("privileged helper SHA-256 does not match the authorized build")

    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app])
    fields = codesign_fields(app)
    if fields.get("TeamIdentifier") != TEAM_ID:
        raise ActivationError(f"unexpected TeamIdentifier: {fields.get('TeamIdentifier')!r}")
    app_entitlements = entitlements(app)
    required = {
        "com.apple.developer.system-extension.install",
        "com.apple.developer.networking.networkextension",
    }
    missing = sorted(required.difference(app_entitlements))
    if missing:
        raise ActivationError(f"required signed entitlements are missing: {', '.join(missing)}")


def copy_signed_app(source: Path, output: Path, force: bool) -> None:
    source_real = source.resolve(strict=True)
    output_real = output.resolve(strict=False)
    if source_real == output_real:
        raise ActivationError("input and output paths must differ")
    if output.suffix != ".app":
        raise ActivationError("output must use the .app suffix")
    if output.exists() and not force:
        raise ActivationError(f"output already exists: {output}; use --force to replace it")

    output.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".stash-561-copy-", dir=output.parent))
    candidate = temp_dir / output.name
    try:
        run(["/usr/bin/ditto", source, candidate])
        validate_app(candidate)
        if output.exists():
            shutil.rmtree(output)
        candidate.rename(output)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def compile_fingerprint_helper(temp_dir: Path) -> Path:
    if not FINGERPRINT_SOURCE.is_file():
        raise ActivationError(f"missing fingerprint source: {FINGERPRINT_SOURCE}")
    helper = temp_dir / "device_fingerprint"
    run(
        [
            "/usr/bin/xcrun",
            "clang",
            "-Wall",
            "-Wextra",
            "-O2",
            "-framework",
            "CoreFoundation",
            "-framework",
            "DiskArbitration",
            "-framework",
            "IOKit",
            "-o",
            helper,
            FINGERPRINT_SOURCE,
        ]
    )
    return helper


def read_fingerprint(platform_override: str | None, disk_override: str | None) -> tuple[str, str]:
    if platform_override is not None and disk_override is not None:
        return platform_override, disk_override
    with tempfile.TemporaryDirectory(prefix="stash-561-fingerprint-") as raw_temp:
        helper = compile_fingerprint_helper(Path(raw_temp))
        values: dict[str, str] = {}
        for line in text_output([helper]).splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = "" if value == "<none>" else value
    platform = platform_override if platform_override is not None else values.get("platform_serial", "")
    disk = disk_override if disk_override is not None else values.get("disk_serial", "")
    if not platform:
        raise ActivationError("IOPlatformSerialNumber is unavailable")
    return platform, disk


def derive_key(device_id: str, platform_serial: str, disk_serial: str) -> bytes:
    material = f"{device_id}-{platform_serial}-{disk_serial}".encode()
    return hashlib.md5(material).hexdigest().upper().encode()


def encrypt_activation(key: bytes) -> bytes:
    proc = run(
        [
            "/usr/bin/openssl",
            "enc",
            "-aes-256-cbc",
            "-K",
            key.hex(),
            "-iv",
            AES_IV.hex(),
        ],
        input_bytes=ACTIVATION_PLAINTEXT,
    )
    return proc.stdout


def self_test() -> None:
    key = derive_key("11111111-2222-3333-4444-555555555555", "Z6QQJQT7FL", "")
    if key != b"9298819223167C9B9F6C83E00B47F6F8":
        raise ActivationError("key derivation self-test failed")
    if encrypt_activation(key) != KNOWN_TEST_CIPHER:
        raise ActivationError("activation encryption self-test failed")


def default_keychain() -> Path:
    output = text_output(["/usr/bin/security", "default-keychain", "-d", "user"])
    return Path(output.strip().strip('"')).expanduser()


def require_user_search_list_keychain(keychain: Path) -> None:
    listed: list[Path] = []
    for line in text_output(["/usr/bin/security", "list-keychains", "-d", "user"]).splitlines():
        value = line.strip().strip('"')
        if not value:
            continue
        candidate = Path(value).expanduser()
        try:
            listed.append(candidate.resolve(strict=True))
        except FileNotFoundError:
            continue
    if keychain not in listed:
        raise ActivationError(
            f"target Keychain is not in the user search list: {keychain}; "
            "add it with security list-keychains before retrying"
        )


def legacy_record_exists(keychain: Path, account: str) -> bool:
    proc = run(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            keychain,
        ],
        check=False,
    )
    if proc.returncode == 0:
        return True
    if proc.returncode == 44:
        return False
    detail = (proc.stderr or proc.stdout).decode(errors="replace").strip()
    raise ActivationError(f"cannot query legacy Keychain record {account}: {detail}")


def require_empty_legacy_slots(keychain: Path) -> None:
    existing = [
        account
        for account in (DEVICE_ACCOUNT, ACTIVATION_ACCOUNT)
        if legacy_record_exists(keychain, account)
    ]
    if existing:
        raise ActivationError(
            "legacy Keychain record already exists: "
            + ", ".join(existing)
            + "; launch Stash to migrate it or delete that exact record before retrying"
        )


def unlock_keychain(keychain: Path, password: str) -> None:
    run_secret(
        ["/usr/bin/security", "unlock-keychain", "-p", password, keychain],
        secret_indexes={3},
    )


def seed_keychain(
    keychain: Path,
    password: str,
    trusted_app: Path,
    device_id: str,
    encrypted: bytes,
) -> None:
    records = (
        (DEVICE_ACCOUNT, DEVICE_LABEL, device_id.encode()),
        (ACTIVATION_ACCOUNT, ACTIVATION_LABEL, encrypted),
    )
    for account, label, value in records:
        run(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-T",
                trusted_app,
                "-a",
                account,
                "-s",
                KEYCHAIN_SERVICE,
                "-l",
                label,
                "-X",
                value.hex(),
                keychain,
            ]
        )
        run_secret(
            [
                "/usr/bin/security",
                "set-generic-password-partition-list",
                "-a",
                account,
                "-s",
                KEYCHAIN_SERVICE,
                "-S",
                f"teamid:{TEAM_ID}",
                "-k",
                password,
                keychain,
            ],
            secret_indexes={9},
        )


def configure_updates(keep_updates: bool) -> None:
    if keep_updates:
        return
    run(["/usr/bin/defaults", "write", APP_ID, "SUEnableAutomaticChecks", "-bool", "false"])
    run(["/usr/bin/defaults", "write", APP_ID, "SUAutomaticallyUpdate", "-bool", "false"])


def wait_for_launch_and_migration(app: Path, keychain: Path) -> None:
    run(["/usr/bin/open", app])
    deadline = time.monotonic() + 20
    saw_process = False
    while time.monotonic() < deadline:
        process = run(["/usr/bin/pgrep", "-x", "Stash"], check=False)
        saw_process = saw_process or process.returncode == 0
        if saw_process and not any(
            legacy_record_exists(keychain, account)
            for account in (DEVICE_ACCOUNT, ACTIVATION_ACCOUNT)
        ):
            return
        time.sleep(0.5)
    if not saw_process:
        raise ActivationError("Stash did not start within 20 seconds")
    raise ActivationError(
        "Stash started but did not consume both legacy activation records within 20 seconds"
    )


def ensure_stash_is_not_running() -> None:
    proc = run(["/usr/bin/pgrep", "-x", "Stash"], check=False)
    if proc.returncode == 0:
        raise ActivationError("Stash is already running; quit it before applying the activation state")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="original signed app")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="signed copy to create")
    parser.add_argument("--device-id", default="11111111-2222-3333-4444-555555555555")
    parser.add_argument("--platform-serial", help="test override; both serial overrides are required")
    parser.add_argument("--disk-serial", help="test override; use an empty string when absent")
    parser.add_argument("--keychain", type=Path, help="target keychain; defaults to the default Keychain")
    parser.add_argument(
        "--keychain-password",
        help="Keychain password; omitted values are read without echo",
    )
    parser.add_argument("--keep-updates", action="store_true", help="retain current Sparkle preferences")
    parser.add_argument("--no-launch", action="store_true", help="do not launch or verify migration")
    parser.add_argument("--dry-run", action="store_true", help="validate and derive only; change nothing")
    parser.add_argument("--force", action="store_true", help="replace an existing output app")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (args.platform_serial is None) != (args.disk_serial is None):
        raise ActivationError("--platform-serial and --disk-serial must be supplied together")

    source = args.input.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve(strict=False)
    self_test()
    validate_app(source)
    platform_serial, disk_serial = read_fingerprint(args.platform_serial, args.disk_serial)
    key = derive_key(args.device_id, platform_serial, disk_serial)
    encrypted = encrypt_activation(key)

    print(f"[+] authorized input: {APP_VERSION} ({APP_BUILD}), Team {TEAM_ID}")
    print(f"[+] platform serial: {platform_serial}")
    print(f"[+] disk serial present: {'yes' if disk_serial else 'no'}")
    print(f"[+] activation record: {len(encrypted)} encrypted bytes")
    if args.dry_run:
        print("[+] dry-run complete; no files, preferences, or Keychain items changed")
        return 0

    ensure_stash_is_not_running()
    keychain = (args.keychain or default_keychain()).expanduser().resolve(strict=True)
    password = args.keychain_password
    if password is None:
        password = getpass.getpass(f"Keychain password for {keychain}: ")
    unlock_keychain(keychain, password)
    require_user_search_list_keychain(keychain)
    require_empty_legacy_slots(keychain)
    copy_signed_app(source, output, args.force)
    seed_keychain(keychain, password, output, args.device_id, encrypted)
    configure_updates(args.keep_updates)
    validate_app(output)
    print(f"[+] signed copy created: {output}")
    print("[+] original Developer ID signature and restricted entitlements preserved")
    print(f"[+] legacy records restricted to TeamIdentifier {TEAM_ID}")
    if args.no_launch:
        print("[+] launch skipped; Stash will migrate the two legacy records on first launch")
    else:
        wait_for_launch_and_migration(output, keychain)
        print("[+] Stash launched and consumed both temporary legacy records")
        print("[+] verify Dashboard, system proxy, and enhanced mode in the UI")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActivationError, FileNotFoundError, PermissionError, plistlib.InvalidFileException) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
