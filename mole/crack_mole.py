#!/usr/bin/env python3
"""crack_mole.py — one-click patcher for Mole.app (v1.15.0/294).

Modes:
  in-place (default): patch the ORIGINAL app in place
      python3 crack_mole.py                          # /Applications/Mole.app
      python3 crack_mole.py --source /path/Mole.app
      python3 crack_mole.py --restore                # revert to latest backup
      python3 crack_mole.py --verify                 # report on-disk patch status

  copy mode: build a patched clone (arm64-thin), original untouched
      python3 crack_mole.py --out output/Mole-Crack.app

  add --open to launch the result afterwards.

  NOTE in-place mode needs the terminal to hold TCC "App Management"
  permission (System Settings > Privacy & Security > App Management),
  granted BEFORE the terminal app was launched — otherwise writing the
  executable fails with EPERM.

In-place details:
  * Full executable backup + a ditto'd .app backup are taken first
    (backups/ next to this script, latest.json remembers which).
  * The fat (universal) Mach-O is patched IN PLACE inside its arm64 slice
    (all patches are length-preserving, so no offsets shift). The x86_64
    slice is NOT patched — arm64 Macs run the arm64 slice; under Rosetta
    the app would be unlicensed.
  * Bundle identity (com.tw93.MoleApp) is kept; Sparkle auto-update is
    disabled so an update cannot silently replace the patched binary.
  * App is re-signed ad-hoc (original dev signature cannot survive edits).

Patches (file offset = vmaddr - 0x100000000 within the arm64 slice):
  A. 0x10033ebd8  CSET W8,EQ -> MOVZ W8,#1
     The only writer of LicenseGate.licensed (ivar +112) in the license
     cluster (verify continuation in the sub_10033EBCC region): forces
     licensed = true regardless of the async verify result => permanent
     offline activation, even with an empty keychain.
  B. 0x100333f50  prologue -> mov w0,#1; mov w1,#0; mov w2,#0; ret
     OfficialBuildVerifier.Verdict := (success, nil) — skips the
     SecCodeCheckValidity "official build" path and its diagnostics.
  C. 0x100b3a6c0  https://live.dodopayments.com -> http://127.0.0.1:23949/localx
     License provider base URL -> loopback lab, so the License… dialog
     accepts ANY key while license_lab_server.py runs (start activate.sh).
     The server must return product_id pdt_0NeAQjL4YEqzkukadjRUT (Mac;
     from the checkout URL at 0xb3a8d0) — pdt_0NoRCskSwjACLFPCWqpn4 is
     the Windows id blacklisted by PersistSuccessfulActivation.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile

KNOWN_FAT_SHA256 = "304d66e17277bc52b13b00caaebb1c0dd9ac22c3040e2eb0324244afeac50136"
KNOWN_THIN_SHA256 = "c16fa322344efaa99ba18d94f23e21b5e2329305c8e079c522f8a0c6b18b5058"
NS_OLD, NS_NEW = b"com.tw93.MoleApp", b"com.tw93.MoleCrk"  # equal length (copy mode only)

PATCHES = [
    (0x10033ebd8, "e8179f1a", "08008052",
     "LicenseGate.licensed := true (CSET W8,EQ -> MOVZ W8,#1)"),
    (0x100333f50, "f85fbca9f65701a9f44f02a9fd7b03a9", "200080d2010080d2020080d2c0035fd6",
     "OfficialBuildVerifier.Verdict -> (success, nil)"),
    (0x100b3a6c0, "68747470733a2f2f6c6976652e646f646f7061796d656e74732e636f6d",
     "687474703a2f2f3132372e302e302e313a32333934392f6c6f63616c78",
     "license provider -> loopback lab (any-key activation UX)"),
    (0x10080e2d8, "ff4301d1f85f01a9", "000080d2c0035fd6",
     "TrialUsageStore.usedCount := 0 (MOV X0,#0; RET) — feature gates that "
     "read the per-feature trialUsage_* keychain counters always see 0 used, "
     "so 'Free trial used up' can never trigger"),
    (0x10032dc58, "fc6fbaa9fa6701a9f85f02a9", "000080d2010080d2c0035fd6",
     "LicenseCredentialStore keychain read := nil (MOV X0,#0;MOV X1,#0;RET) — "
     "the app never calls SecItemCopyMatching, so no keychain access prompts; "
     "it behaves like a fresh install (no stored credentials)"),
]
# post-patch verification signatures: patch bytes + untouched tail context
# (a bare MOV/RET is too common — the tail bytes disambiguate)
PATCH_D_SIG = bytes.fromhex("000080d2c0035fd6") + bytes.fromhex("f65702a9f44f03a9")
PATCH_E_SIG = bytes.fromhex("000080d2010080d2c0035fd6") + bytes.fromhex("f65703a9f44f04a9")

ROOT = pathlib.Path(__file__).resolve().parent
BACKUP_DIR = ROOT / "backups"
BASE = 0x100000000  # arm64 slice vmaddr base (identity file-offset mapping)

# --- signature-based relocators (survive code shifting across versions) ---
SIG_A = bytes.fromhex("c86240b9c92e40f91f010071e8179f1a28c10139")
# LDR W8,[X22,#0x60]; LDR X9,[X22,#0x58]; CMP W8,#0; CSET W8,EQ; STRB W8,[X9,#0x70]
# = the ONLY writer of LicenseGate.licensed. Unique in the whole arm64 slice.
PATCH_A_BYTES = bytes.fromhex("08008052")          # MOVZ W8,#1  (licensed := true)
URL_OLD = b"https://live.dodopayments.com"
URL_NEW = b"http://127.0.0.1:23949/localx"
INTEGRITY_STR = b"integrity: SecRequirementCreateWithString failed"
PATCH_B_BYTES = bytes.fromhex("200080d2010080d2020080d2c0035fd6")
# mov w0,#1; mov w1,#0; mov w2,#0; ret  -> OfficialBuildVerifier.Verdict success
PATCH_D_BYTES = bytes.fromhex("000080d2c0035fd6")
# mov x0,#0; ret  -> TrialUsageStore used-count reader returns 0 forever


def _dword(blob, i):
    return int.from_bytes(blob[i:i + 4], "little")


def _find_all(blob, pat, lo, hi):
    out, i = [], blob.find(pat, lo, hi)
    while i != -1:
        out.append(i)
        i = blob.find(pat, i + 1, hi)
    return out


def _is_prologue_stp_2930(w):
    """STP X29,X30 / X30,X29 (any addressing mode) — prologue fingerprint."""
    return (w >> 24) == 0xA9 and (w & 0x7FF) in (0x3FD, 0x3DE)


def _find_adr_ref(blob, lo, hi, target):
    """File offsets of ADR/ADRP(+ADD) sequences in [lo,hi) referencing vmaddr
    `target` (identity mapping: vmaddr == BASE + slice-relative offset).
    Swift uses both ADRL (ADR+ADD) and ADRP+ADD macros for string literals."""
    hits = []
    for i in range(lo, hi - 8, 4):
        w = _dword(blob, i)
        pc = BASE + (i - lo)
        op = w & 0x9F000000
        if op == 0x10000000:  # ADR
            imm = ((w >> 5) & 0x7FFFF << 2) | ((w >> 29) & 3)
            if imm & 0x100000:
                imm -= 0x200000
            base = pc + imm
        elif op == 0x90000000:  # ADRP
            imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
            if imm & 0x100000:
                imm -= 0x200000
            base = (pc & ~0xFFF) + (imm << 12)
        else:
            continue
        if base == target:
            hits.append(i)
            continue
        w2 = _dword(blob, i + 4)
        if ((w2 & 0xFFC00000) == 0x91000000 and (w2 & 0x1F) == (w & 0x1F)
                and ((w2 >> 5) & 0x1F) == (w & 0x1F)):
            if base + ((w2 >> 10) & 0xFFF) == target:
                hits.append(i)
    return hits


def locate_sites(blob, lo, hi):
    """Locate all three patch sites WITHOUT any offset knowledge.
    Returns dict ea->(before_len, after_bytes, desc). Raises on ambiguity."""
    sites = {}
    # A: unique instruction signature
    hits = _find_all(blob, SIG_A, lo, hi)
    if len(hits) != 1:
        raise SystemExit(f"[!] site A signature found {len(hits)} times (expect 1) "
                         f"— LicenseGate.licensed writer changed; re-analysis needed")
    sites[0x100000000 + (hits[0] + 12 - lo)] = (4, PATCH_A_BYTES,
                                                "LicenseGate.licensed := true")

    # C: provider URL inside arm64 slice
    uh = _find_all(blob, URL_OLD, lo, hi)
    if len(uh) != 1:
        raise SystemExit(f"[!] provider URL found {len(uh)} times in arm64 slice "
                         f"(expect 1) — licensing backend changed")
    sites[0x100000000 + (uh[0] - lo)] = (len(URL_OLD), URL_NEW,
                                         "license provider -> loopback lab")

    # B: integrity-log string -> ADRP reference -> verifier function ->
    #    previous function = Verdict entry (verified adjacent in 1.15.0)
    sh = _find_all(blob, INTEGRITY_STR, lo, hi)
    if len(sh) != 1:
        raise SystemExit(f"[!] integrity string found {len(sh)} times (expect 1)")
    str_ea = BASE + (sh[0] - lo)
    refs = _find_adr_ref(blob, lo, hi, str_ea)
    if len(refs) != 1:
        raise SystemExit(f"[!] integrity-string ADRP refs: {len(refs)} (expect 1)")
    r = refs[0]
    # Walk left to function PROLOGUES: runs of >=3 consecutive 0xA9 STPs whose
    # last is STP X29,X30. Lone in-function STP X29,X30 saves are skipped.
    found = []
    i = r - 4
    while i >= lo and len(found) < 2:
        w = _dword(blob, i)
        if _is_prologue_stp_2930(w):
            j = i
            while j - 4 >= lo and (_dword(blob, j - 4) >> 24) == 0xA9:
                j -= 4
            if (i - j) // 4 + 1 >= 3:  # prologue-shaped STP run
                found.append(j)
                i = j - 4
                continue
        i -= 4
    if len(found) != 2:
        raise SystemExit(f"[!] could not walk back to Verdict function "
                         f"(prologues found: {[hex(BASE + f - lo) for f in found]})")
    b_off = found[1]
    # sanity: B target must start a STP reg-save run itself
    if not all((_dword(blob, b_off + 4 * k) >> 24) == 0xA9 for k in range(4)):
        raise SystemExit("[!] B-site prologue shape mismatch — re-analysis needed")
    sites[BASE + (b_off - lo)] = (16, PATCH_B_BYTES,
                                  "OfficialBuildVerifier.Verdict -> (success,nil)")
    # Site D (trial counter reader) has no stable byte-signature: it is a plain
    # Swift method whose only identity is being called right before the
    # "remaining = 2 - used" check. Refuse unknown versions rather than
    # shipping a half-cracked build whose feature gates still block.
    raise SystemExit(
        "[!] ABORT: site D (TrialUsageStore used-count reader) cannot be "
        "auto-located on an unknown version yet. Sites A/B/C were found, but "
        "without D the feature gates still show 'Free trial used up'.\n"
        "    Re-run the ida-mcp analysis: find the function called by the "
        "'trial.remaining.one' string-referencing UI function right before "
        "its `2 - used` subtraction, add its offset to PATCHES[3].")
    return sites


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fat_arm64_slice(blob: bytes):
    """Return (file_offset, size) of the arm64 slice inside a fat Mach-O,
    or (0, len(blob)) for a thin arm64 binary."""
    magic_be = int.from_bytes(blob[:4], "big")
    swapped = False
    if magic_be not in (0xCAFEBABE, 0xCAFEBABF):
        magic_le = int.from_bytes(blob[:4], "little")
        if magic_le in (0xCAFEBABE, 0xCAFEBABF):
            swapped = True
            magic_be = magic_le
        else:
            return 0, len(blob)  # thin binary
    order = "little" if swapped else "big"
    nfat = int.from_bytes(blob[4:8], order)
    CPU_TYPE_ARM64 = 0x0100000C
    for i in range(nfat):
        rec = blob[8 + 20 * i: 8 + 20 * (i + 1)]
        cputype = int.from_bytes(rec[0:4], order, signed=True)
        off = int.from_bytes(rec[8:12], order)
        size = int.from_bytes(rec[12:16], order)
        if cputype == CPU_TYPE_ARM64:
            return off, size
    sys.exit("[!] ABORT: no arm64 slice found in fat binary")


def apply_sites(blob: bytearray, lo, sites) -> None:
    """sites: iterable of (file_off, before_or_None, after, reason)."""
    for off, before, after, reason in sites:
        if before is not None and bytes(blob[off:off + len(before)]) != before:
            sys.exit(f"[!] ABORT: expected bytes not found at fat off {off}\n"
                     f"    expected {before.hex()}\n"
                     f"    got      {bytes(blob[off:off+len(before)]).hex()}")
        blob[off:off + len(after)] = after
        print(f"[+] patched ea {hex(BASE + off - lo)} (fat off {off}): {reason}")


def resolve_sites(blob, lo, hi, sha, known_sha):
    """Known version -> exact locked offsets; unknown version -> signature scan.
    Returns list of (file_off, before_bytes_or_None, after_bytes, reason)."""
    if sha == known_sha:
        print("[*] version identified: 1.15.0 (294) — using locked offsets")
        return [(lo + (ea - BASE), bytes.fromhex(b), bytes.fromhex(a), r)
                for ea, b, a, r in PATCHES]
    print("[!] unknown version — relocating patch sites by signature")
    out = []
    for ea, (_n, after, reason) in locate_sites(blob, lo, hi).items():
        out.append((lo + (ea - BASE), None, after, reason))
    return out


def resign(app: pathlib.Path) -> None:
    # No --deep: only the main executable and Info.plist were modified; nested
    # code keeps its ORIGINAL signature, so the outer ad-hoc seal stays
    # consistent and a later --restore is a clean byte-level revert.
    macos_dir = app / "Contents/MacOS"
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    main_exe = macos_dir / info["CFBundleExecutable"]
    strays = [p for p in macos_dir.iterdir() if p.is_file() and p != main_exe]
    if strays:
        sys.exit(f"[!] ABORT: stray file(s) in Contents/MacOS/ break codesign "
                 f"('code object is not signed at all'):\n    "
                 + "\n    ".join(str(s) for s in strays))
    r = subprocess.run(["codesign", "--force", "--sign", "-", str(app)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"[!] codesign failed: {r.stderr.strip()}")
    v = subprocess.run(["codesign", "--verify", "--strict", str(app)],
                       capture_output=True, text=True)
    if v.returncode != 0:
        sys.exit(f"[!] codesign verify failed: {v.stderr}")
    print("[+] codesign OK (ad-hoc, outer bundle only)")


def verify_patches(app: pathlib.Path) -> None:
    """Re-read the executable AFTER signing (re-signing can shift fat slice
    offsets!) and confirm the PATCHED signatures are on disk — layout-immune."""
    blob = (app / "Contents/MacOS/Mole").read_bytes()
    lo, size = fat_arm64_slice(blob)
    hi = lo + size
    checks = [
        ("A licensed:=true", SIG_A[:12] + PATCH_A_BYTES + SIG_A[16:]),
        ("B verdict success", PATCH_B_BYTES),
        ("C provider URL", URL_NEW),
        ("D trial used:=0", PATCH_D_SIG),
        ("E no keychain read", PATCH_E_SIG),
    ]
    ok = True
    for name, pat in checks:
        n = len(_find_all(blob, pat, lo, hi))
        mark = "PATCHED" if n == 1 else ("MISSING" if n == 0 else f"AMBIGUOUS({n})")
        ok = ok and n == 1
        print(f"[=] {name}: {mark}")
    if not ok:
        sys.exit("[!] post-sign verification failed")


def tweak_info(app: pathlib.Path, rename: bool) -> None:
    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    # loopback http for patch C + stop Sparkle from replacing the patched binary
    info["NSAppTransportSecurity"] = {"NSAllowsLocalNetworking": True}
    info["SUEnableAutomaticChecks"] = False
    info["SUAutomaticallyUpdate"] = False
    if rename:
        info.update(CFBundleIdentifier=NS_NEW.decode(),
                    CFBundleName="Mole Crack", CFBundleDisplayName="Mole Crack")
    info_path.write_bytes(plistlib.dumps(info))


def patch_in_place(app: pathlib.Path) -> None:
    exe = app / "Contents/MacOS/Mole"
    if not exe.exists():
        sys.exit(f"[!] executable not found: {exe}")
    if subprocess.run(["pgrep", "-x", "Mole"], capture_output=True).returncode == 0:
        print("[*] quitting running Mole first")
        subprocess.run(["killall", "Mole"], capture_output=True)

    blob = bytearray(exe.read_bytes())
    fat_sha = sha256(bytes(blob))
    if fat_sha != KNOWN_FAT_SHA256:
        print(f"[!] WARNING: fat SHA256 {fat_sha} != known-good {KNOWN_FAT_SHA256}\n"
              f"    (byte-level site checks below are the real version lock)")
    lo, size = fat_arm64_slice(bytes(blob))
    hi = lo + size
    print(f"[*] in-place target: {app} (arm64 slice at fat offset {lo}, size {size})")

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    BACKUP_DIR.mkdir(exist_ok=True)
    exe_bak = BACKUP_DIR / f"Mole.exe.{stamp}.bak"
    app_bak = BACKUP_DIR / f"Mole.app.{stamp}.bak"
    plist_bak = BACKUP_DIR / f"Mole.Info.plist.{stamp}.bak"
    sig_dir = app / "Contents/_CodeSignature"
    shutil.copy2(exe, exe_bak)
    shutil.copy2(app / "Contents/Info.plist", plist_bak)
    if sig_dir.exists():
        shutil.copytree(sig_dir, BACKUP_DIR / f"Mole.CodeSignature.{stamp}.bak")
    subprocess.run(["ditto", str(app), str(app_bak)], check=True)
    (BACKUP_DIR / "latest.json").write_text(json.dumps(
        {"exe_backup": str(exe_bak), "app_backup": str(app_bak),
         "plist_backup": str(plist_bak),
         "sig_backup": str(BACKUP_DIR / f"Mole.CodeSignature.{stamp}.bak"),
         "target": str(app), "fat_sha256": fat_sha}, indent=2) + "\n")
    print(f"[+] backup: {exe_bak}\n[+]+ backup: {app_bak}")

    apply_sites(blob, lo, resolve_sites(blob, lo, hi, fat_sha, KNOWN_FAT_SHA256))
    exe.write_bytes(blob)
    exe.chmod(0o755)
    tweak_info(app, rename=False)
    resign(app)
    verify_patches(app)  # re-parse fat offsets AFTER signing (they can shift)
    print(f"[=] patched IN PLACE : {app}")
    print(f"[=] revert anytime   : python3 {pathlib.Path(__file__).name} --restore")


def restore() -> None:
    latest = BACKUP_DIR / "latest.json"
    if not latest.exists():
        sys.exit("[!] no backup record found")
    rec = json.loads(latest.read_text())
    app = pathlib.Path(rec["target"])
    exe = app / "Contents/MacOS/Mole"
    subprocess.run(["killall", "Mole"], capture_output=True)
    # verbatim byte-level restore of executable AND Info.plist, so the
    # original embedded signature (which seals both) becomes valid again —
    # no re-sign needed
    shutil.copy2(rec["exe_backup"], exe)
    exe.chmod(0o755)
    plist_bak = rec.get("plist_backup")
    if plist_bak and pathlib.Path(plist_bak).exists():
        shutil.copy2(plist_bak, app / "Contents/Info.plist")
    sig_bak = rec.get("sig_backup")
    if sig_bak and pathlib.Path(sig_bak).exists():
        sig_dir = app / "Contents/_CodeSignature"
        if sig_dir.exists():
            shutil.rmtree(sig_dir)
        shutil.copytree(sig_bak, sig_dir)
    print(f"[=] restored {app} from {rec['exe_backup']}")


def patch_copy(source: pathlib.Path, out: pathlib.Path, open_it: bool) -> None:
    src_exe = source / "Contents/MacOS/Mole"
    fat = src_exe.read_bytes()
    if sha256(fat) != KNOWN_FAT_SHA256:
        print(f"[!] WARNING: source fat SHA256 differs from known-good "
              f"(site checks below still enforce the lock)")
    with tempfile.TemporaryDirectory() as td:
        thin = pathlib.Path(td) / "thin.arm64"
        thin.write_bytes(fat)
        subprocess.run(["lipo", "-thin", "arm64", str(src_exe), "-output", str(thin)],
                       check=True)
        blob = bytearray(thin.read_bytes())
        print(f"[*] arm64 slice sha256 {sha256(bytes(blob))}")
        thin_sha = sha256(bytes(blob))
        apply_sites(blob, 0, resolve_sites(blob, 0, len(blob), thin_sha, KNOWN_THIN_SHA256))
        cnt = blob.count(NS_OLD)
        if cnt < 1:
            sys.exit("[!] ABORT: namespace string not found — version drifted?")
        blob = blob.replace(NS_OLD, NS_NEW)  # keychain isolation from the original
        print(f"[+] namespace -> {NS_NEW.decode()} ({cnt} sites)")

        if out.exists():
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ditto", str(source), str(out)], check=True)
        target = out / "Contents/MacOS/Mole"
        target.write_bytes(blob)
        target.chmod(0o755)
    tweak_info(out, rename=True)
    resign(out)
    print(f"[=] output        : {out}")
    print(f"[=] binary sha256 : {sha256(bytes(blob))}")
    if open_it:
        subprocess.run(["open", str(out)])


def main() -> int:
    ap = argparse.ArgumentParser(description="One-click Mole patcher")
    ap.add_argument("--source", type=pathlib.Path,
                    default=pathlib.Path("/Applications/Mole.app"))
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="copy mode: build patched clone at this path "
                         "(default is in-place patching of --source)")
    ap.add_argument("--restore", action="store_true",
                    help="restore the last in-place patch from backup")
    ap.add_argument("--verify", action="store_true",
                    help="check on-disk patch status (re-parses fat offsets)")
    ap.add_argument("--open", action="store_true", help="launch afterwards")
    args = ap.parse_args()

    if args.restore:
        restore()
    elif args.verify:
        verify_patches(args.source)
    elif args.out:
        patch_copy(args.source, args.out, args.open)
    else:
        patch_in_place(args.source)
        if args.open:
            subprocess.run(["open", str(args.source)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
