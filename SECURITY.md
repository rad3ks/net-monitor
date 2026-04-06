# Security Policy

## Scope

Net Monitor is a local CLI tool that uses system commands (`traceroute`, `ping`, `curl`) and stores data locally in `~/.net_monitor/`. It does not run a public-facing server — the live dashboard HTTP server binds to localhost only.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately:

1. **Do not** open a public GitHub issue
2. Use [GitHub's private vulnerability reporting](https://github.com/rad3ks/net-monitor/security/advisories/new)
3. Or contact the maintainer via the email in their GitHub profile

You should receive a response within 7 days.

## Known Security Considerations

- **Requires elevated privileges**: `sudo` on macOS/Linux, Administrator on Windows — needed for raw socket access (`traceroute`, TTL-based `ping`)
- **Local HTTP server**: `--live` dashboard binds to `0.0.0.0` on the specified port. Use only on trusted networks
- **Data sensitivity**: Session logs in `~/.net_monitor/` contain your IP, gateway, WiFi SSID, and network topology. Treat them as private when sharing
