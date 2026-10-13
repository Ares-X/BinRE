# E-001 Static analysis

## Sample

- Stash `4.3.2 (561)`, universal `x86_64 + arm64`.
- Main SHA-256:
  `004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f`.
- Helper SHA-256:
  `91bd0c16aab9e1e5c36467d02f853d417a15a2c01bba2fadf741f05eaefa0430`.
- TeamIdentifier: `B36787XSBG`.

## Observations

- The old 487 code offsets and preimages do not match build 561.
- Official IDA MCP confirmed that normal startup does not create onboarding; the post-activation
  event is one path that creates it.
- The system-extension request submit path ends near ARM64 `0x10009c838`; observed references
  include `0x1000a2278`, `0x1000b6ab0`, and `0x1000d094c`.
- System proxy operations use SCPreferences. Enhanced mode uses NETunnelProviderManager and the
  embedded StashTunnel system extension.
- The bundle contains the old privileged Helper manager and SMPrivilegedExecutables declaration,
  but no independent active Helper-install caller was confirmed.
- The legacy Keychain compatibility path accepts two generic-password records and migrates them
  into the app's private access group.

## Finding

Build changes block a fixed-offset patch, but the local activation trust boundary remains replayable.
The strongest final path is not a binary patch: preserve the original signature and supply the legacy
migration state expected by the signed application.
