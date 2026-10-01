#!/usr/bin/env python3
"""Build an isolated ARM64 activation-bypass copy of Stash 4.2.1 (487)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


APP_ID = "ws.stash.app.mac"
APP_VERSION = "4.2.1"
APP_BUILD = "487"
PATCHER_ID = "stash-487-local-patch"
MANIFEST_SCHEMA = 2
MAIN_BINARY_SHA256 = "264e77c91a7e2075227d2a398b3bec77aa78093b6a7e5fcbd63b2207cc02ba69"
HELPER_ID = "ws.stash.app.mac.daemon.helper"
HELPER_SHA256 = "2bc4a146cce06f7a3e0229d26cae997cc0cb892c8847b2dde9dec32cd50e66ce"
ARM64_CPUTYPE = 0x0100000C
X86_64_CPUTYPE = 0x01000007
LC_SEGMENT_64 = 0x19
ADHOC_ENTITLEMENT_ALLOWLIST = {
    "com.apple.security.automation.apple-events",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.personal-information.location",
}

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = SCRIPT_DIR / "Stash 487.app"
DEFAULT_OUTPUT = SCRIPT_DIR / "Stash_487_patched.app"

GO_GETTER_PATCHES = (
    (
        "ActivationInfo.GetActivationState",
        0xD88570,
        bytes.fromhex("600000b4001880b9c0035fd6e0031faac0035fd6"),
        bytes.fromhex("c0038052c0035fd6"),  # mov w0,#30 ; ret
    ),
    (
        "ActivationInfo.GetActivationLicenseType",
        0xD88590,
        bytes.fromhex("600000b4001c80b9c0035fd6e0031faac0035fd6"),
        bytes.fromhex("40008052c0035fd6"),  # mov w0,#2 ; ret
    ),
    (
        "ActivationInfo.GetActivationDeviceType",
        0xD885B0,
        bytes.fromhex("600000b4002080b9c0035fd6e0031faac0035fd6"),
        bytes.fromhex("40008052c0035fd6"),  # mov w0,#2 ; ret
    ),
    (
        "ActivationInfo.GetActivationPlan",
        0xD885D0,
        bytes.fromhex("600000b4002480b9c0035fd6e0031faac0035fd6"),
        bytes.fromhex("80028052c0035fd6"),  # mov w0,#20 ; ret
    ),
)

SWIFT_NORMALIZER_ANCHOR = bytes.fromhex(
    "660a40f9"  # ldr x6,[x19,#0x10]
    "759a15a9"
    "7ba20539"
    "641240f9"
    "64ba00f9"
    "651e40b9"
    "65e20539"
    "48008052"
    "68c200f9"
    "29008052"
    "69220639"
    "618243a9"
    "61ca00f9"
    "632e40b9"
    "63620639"
)

SWIFT_NORMALIZER_PATCHES = (
    ("activationState value", 0, bytes.fromhex("660a40f9"), bytes.fromhex("c6038052")),
    ("activationState tag", 8, bytes.fromhex("7ba20539"), bytes.fromhex("7fa20539")),
    ("licenseType value", 12, bytes.fromhex("641240f9"), bytes.fromhex("44008052")),
    ("licenseType tag", 24, bytes.fromhex("65e20539"), bytes.fromhex("7fe20539")),
    ("deviceType tag", 36, bytes.fromhex("29008052"), bytes.fromhex("09008052")),
    (
        "activationPlan value/tag",
        44,
        bytes.fromhex("618243a961ca00f9632e40b963620639"),
        bytes.fromhex("602240f98102805261ca00f97f620639"),
    ),
)

SIGNING_COMPATIBILITY_PATCHES = (
    (
        "return nil for the CloudKit container unavailable to an ad-hoc signed build",
        0x7F380,
        bytes.fromhex("e0276e94"),  # bl objc_msgSend$containerWithIdentifier:
        bytes.fromhex("000080d2"),  # mov x0,#0
    ),
    (
        "return nil for the CloudDBManager container unavailable to an ad-hoc signed build",
        0x14AA20,
        bytes.fromhex("38fa6a94"),  # bl objc_msgSend$containerWithIdentifier:
        bytes.fromhex("000080d2"),  # mov x0,#0
    ),
)


def run(argv: list[str | os.PathLike[str]]) -> subprocess.CompletedProcess[bytes]:
    printable = " ".join(str(arg) for arg in argv)
    print(f"[*] {printable}")
    proc = subprocess.run([str(arg) for arg in argv], capture_output=True)
    if proc.stdout:
        print(proc.stdout.decode(errors="replace"), end="")
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr.decode(errors="replace"), end="")
        raise SystemExit(f"[!] command failed ({proc.returncode}): {printable}")
    if proc.stderr:
        print(proc.stderr.decode(errors="replace"), end="")
    return proc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(argv: list[str]) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, check=True)
    return (proc.stdout or proc.stderr).strip()


def architecture_name(cpu_type: int) -> str:
    names = {
        ARM64_CPUTYPE: "arm64",
        X86_64_CPUTYPE: "x86_64",
    }
    return names.get(cpu_type, f"cputype-0x{cpu_type:x}")


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_paths(source: Path, output: Path) -> None:
    source_real = source.resolve(strict=True)
    output_real = output.resolve(strict=False)
    if source_real == output_real:
        raise SystemExit("[!] input and output app paths must differ")
    if is_within(output_real, source_real):
        raise SystemExit("[!] output may not be placed inside the input app")
    if is_within(source_real, output_real):
        raise SystemExit("[!] input may not be placed inside the output app")


def manifest_path_for(output: Path) -> Path:
    return output.with_suffix(".patch.json")


def archive_path_for(output: Path) -> Path:
    return output.with_suffix(".zip")


def validate_replaceable_output(output: Path) -> None:
    if output.suffix != ".app":
        raise SystemExit("[!] output must use the .app suffix")
    if output.is_symlink():
        raise SystemExit("[!] refusing to replace a symlink output")

    manifest_path = manifest_path_for(output)
    if not output.exists():
        stale = [path for path in (manifest_path, archive_path_for(output)) if path.exists()]
        if stale:
            joined = ", ".join(str(path) for path in stale)
            raise SystemExit(f"[!] companion output exists without its app: {joined}")
        return

    if not output.is_dir() or not manifest_path.is_file():
        raise SystemExit("[!] refusing to replace an output without its patch manifest")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        info = read_info(output)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise SystemExit(f"[!] existing output is not a valid prior patch result: {exc}") from exc

    target = manifest.get("target", {})
    expected_output = Path(str(manifest.get("output_app", ""))).resolve(strict=False)
    same_target = target == {
        "bundle_id": APP_ID,
        "version": APP_VERSION,
        "build": APP_BUILD,
    }
    bundle_matches = (
        info.get("CFBundleIdentifier") == APP_ID
        and info.get("CFBundleShortVersionString") == APP_VERSION
        and str(info.get("CFBundleVersion")) == APP_BUILD
    )
    known_patcher = manifest.get("patcher", {}).get("id") in (None, PATCHER_ID)
    if not (same_target and bundle_matches and known_patcher and expected_output == output.resolve()):
        raise SystemExit("[!] refusing to replace an app not proven to be this patcher's output")


def read_info(app: Path) -> dict:
    with (app / "Contents" / "Info.plist").open("rb") as handle:
        return plistlib.load(handle)


def validate_target(app: Path) -> Path:
    info = read_info(app)
    got = (
        info.get("CFBundleIdentifier"),
        info.get("CFBundleShortVersionString"),
        str(info.get("CFBundleVersion")),
    )
    want = (APP_ID, APP_VERSION, APP_BUILD)
    if got != want:
        raise SystemExit(f"[!] unsupported app build: got={got!r} want={want!r}")

    binary = app / "Contents" / "MacOS" / "Stash"
    digest = sha256(binary)
    if digest != MAIN_BINARY_SHA256:
        raise SystemExit(f"[!] main binary SHA-256 mismatch: got={digest} want={MAIN_BINARY_SHA256}")

    helper = app / "Contents" / "Library" / "LaunchServices" / HELPER_ID
    helper_digest = sha256(helper)
    if helper_digest != HELPER_SHA256:
        raise SystemExit(f"[!] helper SHA-256 mismatch: got={helper_digest} want={HELPER_SHA256}")
    print(f"[+] target verified: {APP_ID} {APP_VERSION} ({APP_BUILD})")
    return binary


def find_arm64_slice(data: bytes) -> tuple[int, int]:
    if data[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", data, 4)[0]
        matches = []
        for index in range(count):
            entry = 8 + index * 20
            cputype, _, offset, size, _ = struct.unpack_from(">IIIII", data, entry)
            if cputype == ARM64_CPUTYPE:
                matches.append((offset, size))
    elif data[:4] == b"\xca\xfe\xba\xbf":
        count = struct.unpack_from(">I", data, 4)[0]
        matches = []
        for index in range(count):
            entry = 8 + index * 32
            cputype, _, offset, size, _, _ = struct.unpack_from(">IIQQII", data, entry)
            if cputype == ARM64_CPUTYPE:
                matches.append((offset, size))
    elif data[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", data, 4)[0] == ARM64_CPUTYPE:
        matches = [(0, len(data))]
    else:
        matches = []

    if len(matches) != 1:
        raise SystemExit(f"[!] expected one ARM64 slice, found {len(matches)}")
    return matches[0]


def macho_slices(data: bytes) -> list[tuple[int, int, int]]:
    if data[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", data, 4)[0]
        return [
            (
                struct.unpack_from(">I", data, 8 + index * 20)[0],
                struct.unpack_from(">I", data, 8 + index * 20 + 8)[0],
                struct.unpack_from(">I", data, 8 + index * 20 + 12)[0],
            )
            for index in range(count)
        ]
    if data[:4] == b"\xca\xfe\xba\xbf":
        count = struct.unpack_from(">I", data, 4)[0]
        return [
            (
                struct.unpack_from(">I", data, 8 + index * 32)[0],
                struct.unpack_from(">Q", data, 8 + index * 32 + 8)[0],
                struct.unpack_from(">Q", data, 8 + index * 32 + 16)[0],
            )
            for index in range(count)
        ]
    if data[:4] == b"\xcf\xfa\xed\xfe":
        return [(struct.unpack_from("<I", data, 4)[0], 0, len(data))]
    raise SystemExit("[!] unsupported helper Mach-O container")


def slice_layout(binary: Path) -> list[dict[str, object]]:
    full = binary.read_bytes()
    return [
        {
            "architecture": architecture_name(cpu_type),
            "file_offset": f"0x{offset:x}",
            "size": size,
            "sha256": hashlib.sha256(full[offset : offset + size]).hexdigest(),
        }
        for cpu_type, offset, size in macho_slices(full)
    ]


def refresh_main_patch_offsets(binary: Path, records: list[dict[str, object]]) -> None:
    full = binary.read_bytes()
    slice_offset, slice_size = find_arm64_slice(full)
    arm64 = full[slice_offset : slice_offset + slice_size]
    for record in records:
        offset = int(str(record["arm64_offset"]), 16)
        after = bytes.fromhex(str(record["after"]))
        if arm64[offset : offset + len(after)] != after:
            raise SystemExit(f"[!] post-sign patch verification failed: {record['label']}")
        record["file_offset"] = f"0x{slice_offset + offset:x}"


def refresh_helper_patch_offsets(helper: Path, records: list[dict[str, object]]) -> None:
    full = helper.read_bytes()
    by_architecture = {
        architecture_name(cpu_type): (slice_offset, slice_size)
        for cpu_type, slice_offset, slice_size in macho_slices(full)
    }
    for record in records:
        architecture = str(record["architecture"])
        slice_offset, slice_size = by_architecture[architecture]
        macho = full[slice_offset : slice_offset + slice_size]
        plist_offset, _ = info_plist_section(macho)
        info = plistlib.loads(macho[plist_offset : plist_offset + int(record["size"])])
        if info.get("SMAuthorizedClients") != [record["after"]]:
            raise SystemExit(f"[!] post-sign helper pairing verification failed: {architecture}")
        record["file_offset"] = f"0x{slice_offset + plist_offset:x}"


def info_plist_section(macho: bytes) -> tuple[int, int]:
    if macho[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("[!] expected a little-endian 64-bit Mach-O helper slice")
    command_count = struct.unpack_from("<I", macho, 16)[0]
    command_offset = 32
    for _ in range(command_count):
        if command_offset + 8 > len(macho):
            raise SystemExit("[!] truncated helper load-command table")
        command, command_size = struct.unpack_from("<II", macho, command_offset)
        if command_size < 8 or command_offset + command_size > len(macho):
            raise SystemExit("[!] invalid helper load command")
        if command == LC_SEGMENT_64:
            section_count = struct.unpack_from("<I", macho, command_offset + 64)[0]
            section_offset = command_offset + 72
            if section_offset + section_count * 80 > command_offset + command_size:
                raise SystemExit("[!] invalid helper section table")
            for index in range(section_count):
                entry = section_offset + index * 80
                section_name = macho[entry : entry + 16].split(b"\0", 1)[0]
                segment_name = macho[entry + 16 : entry + 32].split(b"\0", 1)[0]
                if section_name == b"__info_plist" and segment_name == b"__TEXT":
                    size = struct.unpack_from("<Q", macho, entry + 40)[0]
                    offset = struct.unpack_from("<I", macho, entry + 48)[0]
                    if offset + size > len(macho):
                        raise SystemExit("[!] helper __info_plist extends beyond its slice")
                    return offset, size
        command_offset += command_size
    raise SystemExit("[!] helper __TEXT,__info_plist section not found")


def fixed_size_plist(value: dict, size: int) -> bytes:
    encoded = plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False)
    trailer = b"</plist>\n"
    if not encoded.endswith(trailer):
        raise SystemExit("[!] unexpected plist serialization format")
    padding_size = size - len(encoded)
    if padding_size < 0:
        raise SystemExit(f"[!] replacement helper plist is {abs(padding_size)} bytes too large")
    encoded = encoded[: -len(trailer)] + (b" " * padding_size) + trailer
    if len(encoded) != size or plistlib.loads(encoded) != value:
        raise SystemExit("[!] failed to construct a fixed-size helper plist")
    return encoded


def patch_helper_authorized_clients(helper: Path) -> list[dict[str, object]]:
    full = bytearray(helper.read_bytes())
    records: list[dict[str, object]] = []
    expected_requirement_fragment = "certificate leaf[subject.OU] = B36787XSBG"
    replacement_requirement = f'identifier "{APP_ID}"'
    architecture_names = {
        ARM64_CPUTYPE: "arm64",
        X86_64_CPUTYPE: "x86_64",
    }

    slices = macho_slices(full)
    if {cpu_type for cpu_type, _, _ in slices} != {ARM64_CPUTYPE, X86_64_CPUTYPE}:
        raise SystemExit("[!] expected universal arm64/x86_64 helper")
    for cpu_type, slice_offset, slice_size in slices:
        macho = bytearray(full[slice_offset : slice_offset + slice_size])
        plist_offset, plist_size = info_plist_section(macho)
        current = bytes(macho[plist_offset : plist_offset + plist_size])
        try:
            info = plistlib.loads(current)
        except Exception as exc:
            raise SystemExit(f"[!] invalid embedded helper plist: {exc}") from exc
        clients = info.get("SMAuthorizedClients")
        if not isinstance(clients, list) or len(clients) != 1:
            raise SystemExit(f"[!] unexpected helper SMAuthorizedClients: {clients!r}")
        if expected_requirement_fragment not in str(clients[0]):
            raise SystemExit("[!] helper client requirement preimage mismatch")
        original_requirement = str(clients[0])
        info["SMAuthorizedClients"] = [replacement_requirement]
        replacement = fixed_size_plist(info, plist_size)
        macho[plist_offset : plist_offset + plist_size] = replacement
        full[slice_offset : slice_offset + slice_size] = macho
        records.append(
            {
                "architecture": architecture_names[cpu_type],
                "section": "__TEXT,__info_plist",
                "file_offset": f"0x{slice_offset + plist_offset:x}",
                "size": plist_size,
                "before": original_requirement,
                "after": replacement_requirement,
            }
        )

    helper.write_bytes(full)
    return records


def unique_offset(data: bytes, needle: bytes, label: str) -> int:
    first = data.find(needle)
    if first < 0:
        raise SystemExit(f"[!] {label}: original byte pattern not found")
    second = data.find(needle, first + 1)
    if second >= 0:
        raise SystemExit(f"[!] {label}: byte pattern is not unique")
    return first


def patch_main_binary(binary: Path) -> list[dict[str, object]]:
    full = bytearray(binary.read_bytes())
    slice_offset, slice_size = find_arm64_slice(full)
    arm64 = bytearray(full[slice_offset : slice_offset + slice_size])
    records: list[dict[str, object]] = []

    anchor = unique_offset(arm64, SWIFT_NORMALIZER_ANCHOR, "Swift ActivationInfo normalizer")
    for label, relative, expected, replacement in SWIFT_NORMALIZER_PATCHES:
        offset = anchor + relative
        current = bytes(arm64[offset : offset + len(expected)])
        if current != expected:
            raise SystemExit(
                f"[!] Swift {label}: preimage mismatch at ARM64+0x{offset:x}: "
                f"got={current.hex()} want={expected.hex()}"
            )
        arm64[offset : offset + len(replacement)] = replacement
        records.append(
            {
                "category": "activation",
                "label": f"Swift {label}",
                "arm64_offset": f"0x{offset:x}",
                "file_offset": f"0x{slice_offset + offset:x}",
                "before": expected.hex(),
                "after": replacement.hex(),
            }
        )

    for label, offset, needle, replacement in GO_GETTER_PATCHES:
        current = bytes(arm64[offset : offset + len(needle)])
        if current != needle:
            raise SystemExit(
                f"[!] {label}: preimage mismatch at ARM64+0x{offset:x}: "
                f"got={current.hex()} want={needle.hex()}"
            )
        before = bytes(arm64[offset : offset + len(replacement)])
        arm64[offset : offset + len(replacement)] = replacement
        records.append(
            {
                "category": "activation",
                "label": f"Go {label}",
                "arm64_offset": f"0x{offset:x}",
                "file_offset": f"0x{slice_offset + offset:x}",
                "before": before.hex(),
                "after": replacement.hex(),
            }
        )

    for label, offset, expected, replacement in SIGNING_COMPATIBILITY_PATCHES:
        current = bytes(arm64[offset : offset + len(expected)])
        if current != expected:
            raise SystemExit(
                f"[!] {label}: preimage mismatch at ARM64+0x{offset:x}: "
                f"got={current.hex()} want={expected.hex()}"
            )
        arm64[offset : offset + len(replacement)] = replacement
        records.append(
            {
                "category": "ad-hoc signing compatibility",
                "label": label,
                "arm64_offset": f"0x{offset:x}",
                "file_offset": f"0x{slice_offset + offset:x}",
                "before": expected.hex(),
                "after": replacement.hex(),
            }
        )

    full[slice_offset : slice_offset + slice_size] = arm64
    binary.write_bytes(full)
    print(f"[+] patched {len(records)} verified ARM64 instruction sites")
    return records


def disable_automatic_updates(app: Path) -> None:
    info_path = app / "Contents" / "Info.plist"
    info = read_info(app)
    info["SUEnableAutomaticChecks"] = False
    info["SUAutomaticallyUpdate"] = False
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=False)
    print("[+] disabled Sparkle automatic checks in the copied app")


def configure_privileged_helper(app: Path) -> dict[str, object]:
    helper = app / "Contents" / "Library" / "LaunchServices" / HELPER_ID
    original_hash = sha256(helper)
    records = patch_helper_authorized_clients(helper)

    info_path = app / "Contents" / "Info.plist"
    info = read_info(app)
    helpers = info.get("SMPrivilegedExecutables")
    if not isinstance(helpers, dict) or set(helpers) != {HELPER_ID}:
        raise SystemExit(f"[!] unexpected SMPrivilegedExecutables: {helpers!r}")
    original_requirement = str(helpers[HELPER_ID])
    if "certificate leaf[subject.OU] = B36787XSBG" not in original_requirement:
        raise SystemExit("[!] main-app helper requirement preimage mismatch")
    replacement_requirement = f'identifier "{HELPER_ID}"'
    helpers[HELPER_ID] = replacement_requirement
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=False)

    run(
        [
            "codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--options",
            "runtime",
            "--identifier",
            HELPER_ID,
            helper,
        ]
    )
    run(["codesign", "--verify", "--strict", "--verbose=4", helper])
    refresh_helper_patch_offsets(helper, records)
    if read_info(app).get("SMPrivilegedExecutables", {}).get(HELPER_ID) != replacement_requirement:
        raise SystemExit("[!] post-write main-app helper requirement verification failed")
    print("[+] repaired the ad-hoc main-app/helper signing pair without changing helper code")
    return {
        "input_sha256": original_hash,
        "output_sha256": sha256(helper),
        "main_app_requirement": {
            "before": original_requirement,
            "after": replacement_requirement,
        },
        "authorized_clients": records,
        "runtime_signature_validation_patched": False,
    }


def extract_entitlements(app: Path) -> bytes:
    proc = run(["codesign", "-d", "--entitlements", ":-", app])
    if not proc.stdout.startswith(b"<?xml"):
        raise SystemExit("[!] failed to extract the original app entitlements")
    return proc.stdout


def filter_entitlements(
    entitlements: bytes,
) -> tuple[bytes, list[str], list[str], list[str], list[str]]:
    original = plistlib.loads(entitlements)
    filtered = {
        key: value
        for key, value in original.items()
        if key in ADHOC_ENTITLEMENT_ALLOWLIST
    }
    filtered["com.apple.security.cs.disable-library-validation"] = True
    preserved = sorted(
        key for key in filtered if key in original and filtered[key] == original[key]
    )
    modified = sorted(
        key for key in filtered if key in original and filtered[key] != original[key]
    )
    added = sorted(set(filtered) - set(original))
    removed = sorted(set(original) - set(filtered))
    return plistlib.dumps(filtered, sort_keys=True), preserved, added, modified, removed


def sign_app(app: Path, entitlements: bytes) -> dict[str, list[str]]:
    filtered_entitlements, preserved, added, modified, removed = filter_entitlements(entitlements)
    with tempfile.TemporaryDirectory(prefix="stash-487-sign-") as temp_dir:
        entitlements_path = Path(temp_dir) / "entitlements.plist"
        entitlements_path.write_bytes(filtered_entitlements)
        run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--options",
                "runtime",
                "--identifier",
                APP_ID,
                "--entitlements",
                entitlements_path,
                app,
            ]
        )
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=4", app])
    print("[+] ad-hoc signature verified; identity-bound entitlements removed")
    return {
        "preserved": preserved,
        "added": added,
        "modified": modified,
        "removed": removed,
    }


def codesign_metadata(app: Path) -> dict[str, str]:
    proc = subprocess.run(
        ["codesign", "-d", "--verbose=4", str(app)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"[!] failed to read final code signature: {proc.stderr.strip()}")
    wanted = {"Identifier", "Format", "CodeDirectory", "Signature", "TeamIdentifier", "CDHash"}
    result: dict[str, str] = {}
    for line in (proc.stdout + proc.stderr).splitlines():
        key, separator, value = line.partition("=")
        if separator and key in wanted:
            result[key] = value
    return result


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def commit_artifacts(pairs: list[tuple[Path, Path]], stage_root: Path) -> None:
    backups: dict[Path, Path] = {}
    committed: list[Path] = []
    try:
        for _, final in pairs:
            if final.exists() or final.is_symlink():
                backup = stage_root / f"previous-{final.name}"
                final.rename(backup)
                backups[final] = backup
        for staged, final in pairs:
            staged.rename(final)
            committed.append(final)
    except Exception:
        for final in reversed(committed):
            remove_path(final)
        for final, backup in backups.items():
            backup.rename(final)
        raise
    for backup in backups.values():
        remove_path(backup)


def build(source: Path, output: Path, *, force: bool, keep_updates: bool) -> None:
    validate_paths(source, output)
    validate_target(source)
    input_entitlements = extract_entitlements(source)

    if output.exists() and not force:
        raise SystemExit(f"[!] output exists (use --force to replace): {output}")
    validate_replaceable_output(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    final_manifest = manifest_path_for(output)
    final_archive = archive_path_for(output)
    stage_root = Path(tempfile.mkdtemp(prefix=f".{output.stem}-build-", dir=output.parent))
    staged_app = stage_root / output.name
    staged_manifest = stage_root / final_manifest.name
    staged_archive = stage_root / final_archive.name

    try:
        run(["ditto", "--rsrc", "--extattr", source, staged_app])
        output_binary = staged_app / "Contents" / "MacOS" / "Stash"
        records = patch_main_binary(output_binary)
        if not keep_updates:
            disable_automatic_updates(staged_app)
        helper_pairing = configure_privileged_helper(staged_app)
        entitlement_changes = sign_app(staged_app, input_entitlements)
        refresh_main_patch_offsets(output_binary, records)
        run(["xattr", "-dr", "com.apple.quarantine", staged_app])
        os.utime(staged_app, None)

        main_layout = slice_layout(output_binary)
        bundle_architectures = [str(item["architecture"]) for item in main_layout]
        run(
            [
                "ditto",
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                staged_app,
                staged_archive,
            ]
        )

        codesign_path = Path(shutil.which("codesign") or "/usr/bin/codesign")
        manifest = {
            "patcher": {
                "id": PATCHER_ID,
                "manifest_schema": MANIFEST_SCHEMA,
                "script_sha256": sha256(Path(__file__).resolve()),
                "python": sys.version.split()[0],
                "macos": command_output(["sw_vers", "-productVersion"]),
                "codesign_path": str(codesign_path),
                "codesign_sha256": sha256(codesign_path),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            "target": {"bundle_id": APP_ID, "version": APP_VERSION, "build": APP_BUILD},
            "input_app": str(source.resolve()),
            "output_app": str(output.resolve()),
            "archive": {
                "path": str(final_archive.resolve()),
                "sha256": sha256(staged_archive),
            },
            "input_main_sha256": MAIN_BINARY_SHA256,
            "output_main_sha256": sha256(output_binary),
            "architectures": {
                "bundle": bundle_architectures,
                "patched": ["arm64"],
                "unpatched": [arch for arch in bundle_architectures if arch != "arm64"],
                "slice_layout": main_layout,
            },
            "automatic_updates": {
                "bundle_defaults_disabled": not keep_updates,
                "updater_implementation_removed": False,
            },
            "runtime_injection": False,
            "port_or_user_configuration_modified": False,
            "window_or_setup_flow_modified": False,
            "helper_modified": True,
            "helper_code_modified": False,
            "helper_pairing": helper_pairing,
            "adhoc_entitlements": entitlement_changes,
            "codesign": codesign_metadata(staged_app),
            "patches": records,
        }
        staged_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        commit_artifacts(
            [
                (staged_app, output),
                (staged_manifest, final_manifest),
                (staged_archive, final_archive),
            ],
            stage_root,
        )
    finally:
        if stage_root.exists():
            shutil.rmtree(stage_root)

    print(f"[+] output: {output}")
    print(f"[+] manifest: {final_manifest}")
    print(f"[+] archive: {final_archive}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="original Stash 487 app")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="new patched app path")
    parser.add_argument("--force", action="store_true", help="replace an existing output app")
    parser.add_argument(
        "--keep-updates",
        action="store_true",
        help="do not disable Sparkle automatic update checks in the copied app",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    build(args.input, args.output, force=args.force, keep_updates=args.keep_updates)


if __name__ == "__main__":
    main()
