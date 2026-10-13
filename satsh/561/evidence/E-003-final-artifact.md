# E-003 Final artifact verification

## Fresh-user script acceptance

```text
[+] authorized input: 4.3.2 (561), Team B36787XSBG
[+] platform serial: Z6QQJQT7FL
[+] disk serial present: no
[+] activation record: 32 encrypted bytes
[+] signed copy created: /Users/Shared/Stash561FinalExact.app
[+] original Developer ID signature and restricted entitlements preserved
[+] legacy records restricted to TeamIdentifier B36787XSBG
[+] Stash launched and consumed both temporary legacy records
```

Post-launch Keychain queries returned `rc=44` for both legacy accounts.

## Integrity

```text
Activation script:
b36233dff0c98d3fef9b31d245d05b8282ad6bc580822ba057d1867a8a1260a3

Verifier:
83a187f1957ba5b547813229e93e04073138cbba818047c01d9991433b20ea8a

Fingerprint helper source:
850778410fc989f6c11e849ccb768d6c9e8382bc73d979e2012070037f484c36

Original main:
004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f

Output main:
004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f

Unchanged helper:
91bd0c16aab9e1e5c36467d02f853d417a15a2c01bba2fadf741f05eaefa0430

TeamIdentifier:
B36787XSBG
```

- `codesign --verify --deep --strict`: passed.
- Source and output bundle inventory: 595 entries, byte-identical.
- Restricted system-extension and network-extension entitlements: preserved.
- Sparkle `SUEnableAutomaticChecks`: `0`.
- Sparkle `SUAutomaticallyUpdate`: `0`.
- Output size remains approximately 218 MB; no 1.84 GB duplication.

## Finding

The delivered `Stash 561 Patched.app` is a signature-preserving copy, not a modified binary.
Activation is per-user external state established by `activate_stash_561.py`.
