# E-002 VM runtime validation

## Environment

- Parallels Desktop VM, macOS 26.6.2 ARM64.
- Fresh disposable user Home and login Keychain for final script acceptance.
- Original host application and host Keychain left untouched.

## Passed observations

- Final script exited 0 and Stash consumed both temporary Keychain records.
- Startup showed the normal menu immediately, with no Stash Setup or license dialog.
- Original Developer ID system extension installed and remained activated/enabled after reboot.
- Test subscription loaded 47,442 rules, proxy groups, Dashboard data and external IP.
- Explicit HTTP proxy traffic through `127.0.0.1:7890` used exit IP `58.176.134.116`.
- System proxy ON configured HTTP/HTTPS/SOCKS at `127.0.0.1:7890`; Safari used the proxy IP.
- System proxy OFF restored all three proxy types to disabled.
- Enhanced mode kept system proxy disabled, created `utun4` with `198.18.0.1/16`, and installed
  the default tunnel route; direct curl and Safari used the proxy IP.
- Enhanced mode OFF removed the tunnel route and restored the default route to `en0`.
- After reboot, authorization, subscription, rules, system extension and VPN configuration persisted.
- System proxy and enhanced mode were each re-enabled and restored to OFF after reboot.

## Evidence images

- `E-077-signed-original-dashboard-full-function.png`
- `E-078-reboot-persisted-dashboard.png`
- `E-079-reboot-enhanced-mode-on.png`
- `E-080-reboot-system-proxy-on.png`
- `E-081-reboot-system-proxy-safari.png`
- `E-082-fresh-user-final-script.png`

## Finding

All requested product paths work when the original signed bytes are preserved. The earlier failures
were caused by ad-hoc re-signing, not by an independent product limitation.
