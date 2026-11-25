# Architecture

## Proposed stack
Rust CLI first; Tauri 2 and a small TypeScript UI after connectivity. Use the official sing-box standalone executable as an external managed engine where suitable, rather than implementing packet transport or embedding a second VPN stack. Confirm supported config schema and platform capabilities against a pinned version. Use Rust modules/crates only where the boundary is meaningful. Reassess framework/version choices when scaffolding.

## Components
- Provider: typed capabilities, authorized credential acquisition, endpoints, expiry, error classes. Windscribe first, mock provider for tests. Never assume a general account password is a proxy password.
- Engine: validates generated config against pinned executable, verifies trusted binary provenance/checksum, starts/stops owned process, captures sanitized diagnostics, handles timeouts and unexpected exits.
- Connection controller: owns state transitions `Disconnected -> Preparing -> Connecting -> Verifying -> Connected -> Disconnecting -> Disconnected`; errors and cancellation explicit. Single active connection, bounded retries; no hidden direct fallback.
- Health check: test actual traffic through the selected transport, including validated destination TLS and a public IP response. Distinguish DNS, TCP, TLS, proxy authorization, target reachability, and cancellation failures. An IP alone does not prove network-wide routing.
- Network manager (later): Windows routes, interface, DNS, kill switch, and restoration. Keep privileges minimal; plan/snapshot/apply/verify/rollback. Track only changes owned by WindLab; do not delete unrelated routes. Detect conflicts with existing VPNs, decline by default.
- Secret store: Windows Credential Manager or OS-backed equivalent for explicitly approved persistence; use short-lived memory by default; no secrets in command lines, config logs, or repository. Restrict and remove any runtime config containing secrets.
- UI (later): separate from engine; show provider capability and mode (proxy-only vs TUN), accurate status and actionable errors. No secrets returned via unrestricted IPC.

## Data flow
Application -> explicit loopback proxy (phase 1) or TUN (phase 3) -> sing-box -> TLS HTTP CONNECT upstream -> destination. Verify certificate and hostname for both the upstream and destination. HTTP CONNECT is primarily TCP; reject unsupported UDP instead of sending direct. DNS through an approved protected route must be validated; no global mode until tested.

## Proposed source layout
`crates/core/`, `crates/cli/`, `src-tauri/`, `ui/`, `tests/`, `docs/`. Do not create placeholders unnecessarily. Keep provider-specific logic out of generic routing code. Phase 1 may use one crate and a few modules.
