#!/usr/bin/env python3
"""Verify a Stash 4.2.1 (487) patch result and its provenance manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import subprocess
import sys
import zipfile
from pathlib import Path

import patch_stash_487 as patcher


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_APP = SCRIPT_DIR / "Stash_487_patched.app"


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"cannot read manifest {path}: {exc}")
    check(isinstance(value, dict), "manifest root must be an object")
    return value


def verify_manifest_identity(manifest: dict) -> None:
    patcher_info = manifest.get("patcher", {})
    check(patcher_info.get("id") == patcher.PATCHER_ID, "unexpected patcher id")
    check(
        patcher_info.get("manifest_schema") == patcher.MANIFEST_SCHEMA,
        "unsupported manifest schema",
    )
    check(
        manifest.get("target")
        == {
            "bundle_id": patcher.APP_ID,
            "version": patcher.APP_VERSION,
            "build": patcher.APP_BUILD,
        },
        "manifest target does not identify Stash 4.2.1 (487)",
    )
    check(
        manifest.get("input_main_sha256") == patcher.MAIN_BINARY_SHA256,
        "manifest input hash does not match the supported original",
    )
    check(manifest.get("runtime_injection") is False, "runtime injection is unexpected")
    check(
        manifest.get("port_or_user_configuration_modified") is False,
        "manifest reports a port or user-configuration modification",
    )
    check(
        manifest.get("window_or_setup_flow_modified") is False,
        "manifest reports a window or Setup-flow modification",
    )
    check(manifest.get("helper_code_modified") is False, "helper code was modified")


def verify_script_provenance(manifest: dict, script: Path) -> None:
    expected = manifest.get("patcher", {}).get("script_sha256")
    check(isinstance(expected, str), "manifest has no patcher script hash")
    check(script.is_file(), f"patcher script is missing: {script}")
    check(patcher.sha256(script) == expected, "patcher script hash does not match manifest")
    print(f"[+] patcher provenance: {expected}")


def verify_bundle_identity(app: Path) -> tuple[Path, Path, dict]:
    check(app.is_dir() and not app.is_symlink(), f"app is not a regular bundle: {app}")
    try:
        info = patcher.read_info(app)
    except (OSError, plistlib.InvalidFileException) as exc:
        fail(f"cannot read app Info.plist: {exc}")
    got = (
        info.get("CFBundleIdentifier"),
        info.get("CFBundleShortVersionString"),
        str(info.get("CFBundleVersion")),
    )
    want = (patcher.APP_ID, patcher.APP_VERSION, patcher.APP_BUILD)
    check(got == want, f"unexpected app identity: got={got!r} want={want!r}")
    binary = app / "Contents" / "MacOS" / "Stash"
    helper = app / "Contents" / "Library" / "LaunchServices" / patcher.HELPER_ID
    check(binary.is_file(), f"main executable is missing: {binary}")
    check(helper.is_file(), f"privileged helper is missing: {helper}")
    return binary, helper, info


def verify_patch_bytes(binary: Path, manifest: dict) -> None:
    full = binary.read_bytes()
    slice_offset, slice_size = patcher.find_arm64_slice(full)
    arm64 = full[slice_offset : slice_offset + slice_size]
    records = manifest.get("patches")
    patched_anchor = bytearray(patcher.SWIFT_NORMALIZER_ANCHOR)
    for _label, relative, before, after in patcher.SWIFT_NORMALIZER_PATCHES:
        check(
            bytes(patched_anchor[relative : relative + len(before)]) == before,
            "patcher Swift normalizer definition is inconsistent",
        )
        patched_anchor[relative : relative + len(after)] = after
    anchor_offset = arm64.find(patched_anchor)
    check(anchor_offset >= 0, "Swift normalizer anchor is missing")
    check(
        arm64.find(patched_anchor, anchor_offset + 1) < 0,
        "Swift normalizer anchor is not unique",
    )

    expected_records: list[tuple[str, str, int, bytes, bytes]] = []
    for label, relative, before, after in patcher.SWIFT_NORMALIZER_PATCHES:
        expected_records.append(("activation", f"Swift {label}", anchor_offset + relative, before, after))
    for label, offset, preimage, after in patcher.GO_GETTER_PATCHES:
        expected_records.append(("activation", f"Go {label}", offset, preimage[: len(after)], after))
    for label, offset, before, after in patcher.SIGNING_COMPATIBILITY_PATCHES:
        expected_records.append(("ad-hoc signing compatibility", label, offset, before, after))
    for label, offset, before, after in patcher.HELPER_COLD_START_COMPATIBILITY_PATCHES:
        expected_records.append(("ad-hoc helper compatibility", label, offset, before, after))

    expected_count = len(expected_records)
    check(
        isinstance(records, list) and len(records) == expected_count,
        f"expected {expected_count} patch records",
    )

    occupied: list[tuple[int, int, str]] = []
    for record, expected_record in zip(records, expected_records):
        check(isinstance(record, dict), "invalid patch record")
        expected_category, expected_label, expected_offset, expected_before, expected_after = expected_record
        label = str(record.get("label", "unnamed patch"))
        check(record.get("category") == expected_category, f"{label}: unexpected patch category")
        check(label == expected_label, f"unexpected patch label: {label}")
        try:
            offset = int(str(record["arm64_offset"]), 16)
            recorded_before = bytes.fromhex(str(record["before"]))
            recorded_after = bytes.fromhex(str(record["after"]))
            recorded_file_offset = int(str(record["file_offset"]), 16)
        except (KeyError, ValueError) as exc:
            fail(f"{label}: malformed patch metadata: {exc}")
        check(offset == expected_offset, f"{label}: unexpected ARM64 offset")
        check(recorded_before == expected_before, f"{label}: unexpected preimage bytes")
        check(recorded_after == expected_after, f"{label}: unexpected replacement bytes")
        end = offset + len(recorded_after)
        check(end <= len(arm64), f"{label}: patch extends beyond ARM64 slice")
        check(
            arm64[offset:end] == recorded_after,
            f"{label}: output bytes do not match manifest at ARM64+0x{offset:x}",
        )
        check(
            recorded_file_offset == slice_offset + offset,
            f"{label}: manifest file offset does not match FAT layout",
        )
        for prior_start, prior_end, prior_label in occupied:
            check(
                end <= prior_start or offset >= prior_end,
                f"{label}: overlaps patch record {prior_label}",
            )
        occupied.append((offset, end, label))
    print(f"[+] patch bytes: {expected_count}/{expected_count} ARM64 records match")


def verify_helper_pairing(helper: Path, info: dict, manifest: dict) -> None:
    pairing = manifest.get("helper_pairing")
    check(isinstance(pairing, dict), "helper pairing metadata is missing")
    expected_hash = pairing.get("output_sha256")
    check(isinstance(expected_hash, str), "helper output hash is missing")
    check(pairing.get("input_sha256") == patcher.HELPER_SHA256, "unexpected original helper hash")
    check(patcher.sha256(helper) == expected_hash, "helper hash does not match manifest")

    main_requirement = pairing.get("main_app_requirement", {}).get("after")
    check(isinstance(main_requirement, str), "main-app helper requirement is missing")
    check(
        info.get("SMPrivilegedExecutables", {}).get(patcher.HELPER_ID) == main_requirement,
        "main-app helper requirement does not match manifest",
    )

    records = pairing.get("authorized_clients")
    check(isinstance(records, list) and len(records) == 2, "expected two helper slice records")
    check(
        pairing.get("runtime_signature_validation_patched") is False,
        "runtime helper signature validation was unexpectedly patched",
    )
    full = helper.read_bytes()
    slices = {
        patcher.architecture_name(cpu_type): (offset, size)
        for cpu_type, offset, size in patcher.macho_slices(full)
    }
    check(set(slices) == {"x86_64", "arm64"}, "unexpected helper architectures")
    recorded_architectures: set[str] = set()
    for record in records:
        architecture = str(record.get("architecture"))
        check(architecture in slices, f"helper slice is missing: {architecture}")
        check(architecture not in recorded_architectures, f"duplicate helper slice: {architecture}")
        recorded_architectures.add(architecture)
        slice_offset, slice_size = slices[architecture]
        macho = full[slice_offset : slice_offset + slice_size]
        plist_offset, plist_size = patcher.info_plist_section(macho)
        embedded = plistlib.loads(macho[plist_offset : plist_offset + plist_size])
        expected_requirement = record.get("after")
        check(
            embedded.get("SMAuthorizedClients") == [expected_requirement],
            f"{architecture} helper authorized-client requirement does not match",
        )
        check(
            int(str(record.get("file_offset")), 16) == slice_offset + plist_offset,
            f"{architecture} helper plist offset does not match FAT layout",
        )
    check(recorded_architectures == {"x86_64", "arm64"}, "helper slice records are incomplete")
    print(f"[+] helper pairing: {expected_hash}")


def verify_update_defaults(info: dict, manifest: dict) -> None:
    disabled = manifest.get("automatic_updates", {}).get("bundle_defaults_disabled")
    check(isinstance(disabled, bool), "automatic-update policy is missing")
    if disabled:
        check(info.get("SUEnableAutomaticChecks") is False, "automatic checks are not disabled")
        check(info.get("SUAutomaticallyUpdate") is False, "automatic installation is not disabled")
        print("[+] automatic updates: bundle defaults disabled")
    else:
        print("[+] automatic updates: original bundle defaults retained")


def codesign_details(app: Path) -> dict[str, str]:
    proc = subprocess.run(
        ["codesign", "-d", "--verbose=4", str(app)],
        capture_output=True,
        text=True,
        check=False,
    )
    check(proc.returncode == 0, f"cannot read app signature: {proc.stderr.strip()}")
    result: dict[str, str] = {}
    for line in (proc.stdout + proc.stderr).splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    return result


def verify_signature(app: Path, manifest: dict) -> None:
    proc = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(app)],
        capture_output=True,
        text=True,
        check=False,
    )
    check(proc.returncode == 0, f"code signature verification failed: {proc.stderr.strip()}")
    actual = codesign_details(app)
    expected = manifest.get("codesign", {})
    for key in ("Identifier", "Signature", "TeamIdentifier", "CDHash"):
        check(actual.get(key) == expected.get(key), f"code-sign field differs: {key}")
    print(f"[+] code signature: CDHash {actual.get('CDHash')}")


def verify_entitlements(app: Path, manifest: dict) -> None:
    proc = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(app)],
        capture_output=True,
        check=False,
    )
    check(proc.returncode == 0, "cannot extract app entitlements")
    start = proc.stdout.find(b"<?xml")
    check(start >= 0, "codesign did not return an entitlement plist")
    try:
        actual = plistlib.loads(proc.stdout[start:])
    except plistlib.InvalidFileException as exc:
        fail(f"invalid entitlement plist: {exc}")
    changes = manifest.get("adhoc_entitlements", {})
    for key in changes.get("removed", []):
        check(key not in actual, f"removed entitlement is still present: {key}")
    for key in changes.get("preserved", []) + changes.get("added", []):
        check(key in actual, f"expected entitlement is missing: {key}")
    check(
        set(actual) == patcher.ADHOC_ENTITLEMENT_ALLOWLIST,
        "ad-hoc entitlement set differs from the patcher allowlist",
    )
    print(f"[+] entitlements: {len(actual)} keys, identity-bound keys absent")


def zip_member_sha256(bundle: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    try:
        with bundle.open(name) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except KeyError:
        fail(f"archive member is missing: {name}")
    return digest.hexdigest()


def verify_archive(archive: Path, app: Path, manifest: dict) -> None:
    check(archive.is_file(), f"archive is missing: {archive}")
    expected = manifest.get("archive", {}).get("sha256")
    check(isinstance(expected, str), "archive hash is missing from manifest")
    check(patcher.sha256(archive) == expected, "archive hash does not match manifest")
    try:
        with zipfile.ZipFile(archive) as bundle:
            bad_member = bundle.testzip()
            check(bad_member is None, f"archive CRC failure: {bad_member}")
            prefix = app.name + "/"
            names = bundle.namelist()
            check(any(name.startswith(prefix) for name in names), "archive has no app bundle")
            check(
                all(name.startswith(prefix) or name.startswith("__MACOSX/") for name in names),
                "archive contains an unexpected top-level member",
            )
            critical_members = (
                "Contents/MacOS/Stash",
                f"Contents/Library/LaunchServices/{patcher.HELPER_ID}",
                "Contents/Info.plist",
                "Contents/_CodeSignature/CodeResources",
            )
            for relative in critical_members:
                check(
                    zip_member_sha256(bundle, prefix + relative) == patcher.sha256(app / relative),
                    f"archive member differs from the verified app: {relative}",
                )
    except zipfile.BadZipFile as exc:
        fail(f"invalid ZIP archive: {exc}")
    print(f"[+] archive: {expected}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=DEFAULT_APP, help="patched app bundle")
    parser.add_argument("--manifest", type=Path, help="patch manifest; defaults beside the app")
    parser.add_argument("--archive", type=Path, help="ZIP archive; defaults beside the app")
    parser.add_argument(
        "--patcher",
        type=Path,
        default=SCRIPT_DIR / "patch_stash_487.py",
        help="patcher script whose hash must match the manifest",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = args.app.resolve(strict=False)
    manifest_path = (args.manifest or app.with_suffix(".patch.json")).resolve(strict=False)
    archive = (args.archive or app.with_suffix(".zip")).resolve(strict=False)

    manifest = load_manifest(manifest_path)
    verify_manifest_identity(manifest)
    verify_script_provenance(manifest, args.patcher.resolve(strict=False))
    binary, helper, info = verify_bundle_identity(app)
    check(
        patcher.sha256(binary) == manifest.get("output_main_sha256"),
        "main executable hash does not match manifest",
    )
    verify_patch_bytes(binary, manifest)
    verify_helper_pairing(helper, info, manifest)
    verify_update_defaults(info, manifest)
    verify_signature(app, manifest)
    verify_entitlements(app, manifest)
    verify_archive(archive, app, manifest)
    print("[+] verification complete: all checks passed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("[!] interrupted")
