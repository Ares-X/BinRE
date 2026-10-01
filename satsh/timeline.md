# Timeline (append-only)

## 2026-10-01T18:15:00+08:00 | primary | static-diff

- action: Exported targeted build-487 functions and completed the 482/487 Diaphora comparison.
- evidence_ids: [E-001, E-003, E-009]

## 2026-10-01T18:20:00+08:00 | primary | correction

- action: Confirmed the old `0x61b0xx` patch area belongs to Starscream and located the true build-487 activation getters.
- evidence_ids: [E-002, E-003]

## 2026-10-01T19:06:00+08:00 | primary | patch-build

- action: Built the revised 12-site ARM64 patch and repaired the main-app/Helper ad-hoc signing pair.
- evidence_ids: [E-004]

## 2026-10-01T19:12:00+08:00 | primary | vm-helper

- action: Confirmed the patched app and installed Helper survived the VM reboot.
- evidence_ids: [E-007]

## 2026-10-01T19:23:00+08:00 | primary | vm-config

- action: Removed the stale `127.0.0.1:7897` system proxy and installed the private test subscription in Stash.
- evidence_ids: [E-005]

## 2026-10-01T19:24:00+08:00 | primary | vm-proxy

- action: Confirmed proxy groups, latency results, and direct/proxied HTTP 204 responses.
- evidence_ids: [E-005, E-008]

## 2026-10-01T19:25:00+08:00 | primary | restart

- action: Terminated exact PID 424, relaunched as PID 1267, and confirmed activation/configuration persistence with no new crash report.
- evidence_ids: [E-006, E-007]

## 2026-10-01T19:29:00+08:00 | primary | delivery

- action: Rebuilt the canonical app transactionally and completed code-signature and ZIP integrity checks.
- evidence_ids: [E-004]

## 2026-10-02T00:48:00+08:00 | primary | helper-compatibility

- action: Rebuilt the VM-native canonical artifact with three 15-to-30-second Helper probe deadline changes and manifest schema 3.
- evidence_ids: [E-004, E-011]

## 2026-10-02T00:50:00+08:00 | primary | cold-reboot

- action: Cold-rebooted Parallels Desktop 27.0.2, observed the real Helper listener within 0.35 seconds, and confirmed no Helper prompt after the extended deadline.
- evidence_ids: [E-011]

## 2026-10-02T00:59:00+08:00 | primary | final-uat

- action: Opened the dashboard using a guest-local input event, confirmed proxy group loading and latency, and repeated direct/proxied HTTP 204 probes.
- evidence_ids: [E-012]

## 2026-10-02T01:07:00+08:00 | primary | final-delivery

- action: Retrieved the VM-native ZIP and manifest, then reran the independent verifier against the extracted host copy.
- evidence_ids: [E-004, E-010]
