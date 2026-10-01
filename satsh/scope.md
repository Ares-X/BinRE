# Stash 482 to 487 authentication diff

## auth

- status: granted
- basis: User-owned application and explicit authorization for static analysis, patch construction, administrator operations, Helper installation, configuration tests, proxy tests, and process restarts inside the dedicated VM.

## in_scope

- assets:
  - `<build-482-app>`
  - `<build-487-app>`
  - repository directory `satsh/`
  - dedicated VM staging directory
- goal: Determine whether the build-482 activation-bypass approach maps to build 487, produce a fail-closed one-click patcher, and validate the ARM64 output end to end.

## network_profile

- mode: lab_only
- allowed: User-provided test subscription endpoint and low-impact connectivity probes from the dedicated VM.
- prohibited: Third-party account creation, production data mutation, and unrelated scanning.

## signoff

- ready_for_act: true
- approved_by: application owner

## boundaries

- Host originals remain read-only; patched applications are not launched or installed on the host.
- VM application launch, Helper installation, user configuration, system proxy cleanup, and network validation are allowed.
- VM credentials and the private subscription URL are not written to reports or patch-package documentation.
- x86_64 runtime validation, production Apple signing/notarization, production CloudKit/iCloud behavior, and server-side Stash infrastructure are out of scope.
