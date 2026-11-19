# Changelog

## 1.0.4 - 2026-11-19

- Follow the upstream repository through c64ead3, documenting macOS equivalents and the remaining per-application filtering boundary.
- Use a fixed privileged PATH and reject unsafe installation path ownership, write permissions, ACLs and symlinks.
- Verify a bound physical-interface TCP decoy with scoped routes and labelled pf packet evidence; read back rule restoration and exact route cleanup. Distinguish failure (1) from unverified (2).
- Refuse to report successful uninstall when daemon shutdown, rule removal or state restoration fails.
- Add a separate optional Python network diagnostic with local-only defaults, explicit HTTPS-proxy/STUN probes and redacted output.
- Expand offline regression coverage, including complete verification success, unverified evidence and restoration/cleanup failures.

## 1.0.3 - 2026-11-19

- Validate both official inbound IPv4 ranges and IPv6/NAT64 tables in the live kernel, together with exact outbound block rules on every physical interface and the root anchor reference.
- Report incomplete protection as a failure; distinguish a registered daemon from a running daemon.
- Preserve launchd registration during upgrades and retry transient registration failures on new installs.
- Reload only the managed anchor when the main configuration is unchanged; preserve initial uninstall state.
- Add offline regression coverage for stale tables, missing interfaces, incorrect rules, and daemon upgrades.

## 1.0.2 - 2026-11-09

- Add Anthropic's newly published inbound IPv4 range to the physical-interface block table.
- Reinstalling this release refreshes the managed `pf` anchor with both current inbound IPv4 ranges.

## 1.0.1 - 2026-10-31

- Use the absolute installed path in post-install commands and guidance.
- Preserve the executable bit for the main script in Git.
- Remove an unused IPv6 constant; public IPv6 and NAT64 blocking is unchanged.

## 1.0.0 - 2026-10-31

- Initial public release; public versioning starts at 1.0.0.
- Physical-interface blocking for Anthropic IPv4.
- Public IPv6 and NAT64 blocking while preserving local IPv6 scopes.
- Boot-time root LaunchDaemon with runtime self-healing.
- Reversible `pf.conf` integration and state-aware uninstall.
- Non-Anthropic A/B verification flow.
