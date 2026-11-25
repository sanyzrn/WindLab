# Windows validation matrix

## Phase 1–2 (no OS changes)
- Valid config, malformed host/port, missing credentials, header injection, redaction and secret lifetime.
- Local TLS fixture: valid certificate, invalid certificate, wrong hostname, proxy 407/403, timeout, disconnect, valid CONNECT response with buffered bytes. Use test certificates trusted only by the isolated fixture; never add to system trust.
- End-to-end destination TLS, HTTP response status and IP validation; prove test cannot silently use direct network or ambient proxy environment.
- Loopback-only listener, port conflict, lifecycle, concurrent clients, cancellation, unexpected engine exit, no credential echo. UDP rejected if unsupported.
- With owner approval: baseline official extension and desktop, then test WindLab with Speedo off. Owner controls existing VPN state. Record timestamps, network type (no identifying details), results and elapsed time; do not log account data.

## Phase 3 (admin and explicit consent required)
- Snapshot routes, DNS, interface metrics, proxy/firewall settings; test in VM first. Restore snapshot or remove only owned changes; verify after each case.
- Existing VPN detection; fail safely without altering it. Connect/disconnect, repeated cycle, suspend/resume, network change, engine kill, app kill, startup recovery.
- Confirm public exit IP via multiple tools; verify DNS goes through intended route and IPv6, UDP/QUIC, WebRTC do not escape protected mode. A blocked unsupported protocol is acceptable if clearly stated.
- Failure/kill-switch behavior with outbound traffic continuously attempted; fail closed in protected mode, explicit disconnect restores prior normal connectivity according to policy.
- Validate domestic split-routing only when user opts in; confirm intentional direct routes separately from leaks.

## CI
Windows and Linux unit/integration fixture tests, formatting, lint, dependency review and build. No live provider credentials or privileged networking in hosted CI. Report platform limitations. Live tests are manual with owner authorization. No claim of all tests passing until executed.
