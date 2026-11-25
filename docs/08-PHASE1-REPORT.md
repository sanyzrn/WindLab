# Phase 0/1 report — 2026-11-25

Branch: `feature/windscribe-proof`. Toolchain: rustc/cargo 1.100.0 (stable-x86_64-pc-windows-msvc). All tests executed locally on Windows 11 x64; CI workflow added but not yet run on GitHub at the time of writing.

## Scope delivered
- Phase 0 research with pinned sources and an explicit provider-access blocker (see `docs/03-RESEARCH.md`, "Verified findings").
- Phase 1 minimal CLI proof: `windlab-proof` (single crate `windlab`, lib + bin).
- Local-only TLS fixture test suite; no real credentials, no external network needed, no OS network changes anywhere.

## What the proof does
`windlab-proof --proxy-host <host> [--proxy-port 443] [--target-url https://api.ipify.org/] [--timeout-secs 30]`

1. Resolves and TCP-connects to the explicitly configured proxy (ambient `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are deliberately ignored).
2. TLS to the proxy with strict WebPKI certificate + hostname validation (rustls, ring provider; no insecure mode, no custom CA).
3. HTTP CONNECT to the target authority. Credentials are prompted interactively (password without echo), never accepted via argv/env, zeroized on drop, redacted in all debug/error output. Basic auth is sent only after a 407 Basic challenge, only to the TLS-verified proxy, never to the destination.
4. End-to-end TLS to the destination through the tunnel, one HTTP GET, strict validation that the body is a bare IP address.
5. Prints per-stage timings and the exit IP. Any failure aborts with a classified error and a stable exit code (config=2, dns=3, tcp=4, proxy-tls=5, proxy-auth=6, proxy-protocol=7, destination-tls=8, destination-http=9, invalid-ip=10, timeout=11, cancelled=12). **No direct fallback exists.**

Bytes coalesced with the CONNECT response are preserved (`PrefixedStream`). Header injection via host/credentials is rejected at validation. Response heads are bounded (16 KiB) and bodies (64 KiB). Ctrl-C cancels cleanly; phase 1 owns no subprocesses and changes no OS state.

## Tests executed (actual results)
`cargo test --locked` on Windows, 2026-11-25: **26 passed, 0 failed, 0 ignored** (5 unit + 21 fixture).
`cargo clippy --locked --all-targets -- -D warnings`: clean. `cargo fmt --all --check`: clean. `cargo build --locked --release`: success; `windlab-proof --help` verified.

Fixture coverage (all servers on 127.0.0.1, per-run certificates trusted only by the fixture root store):
- Success with 407 challenge auth; success without auth; ambient-proxy env ignored.
- Wrong password (407), missing credentials on 407, repeated 407, 403 — all `proxy-auth`, no secret echo.
- Untrusted proxy cert, wrong proxy hostname → `proxy-tls`; untrusted destination cert, wrong destination hostname → `destination-tls`.
- Silent proxy → `timeout` at `connect`; proxy disconnect after CONNECT → `proxy-protocol`; buffered bytes after 200 preserved.
- Destination non-200 → `destination-http`; non-IP body → `invalid-ip`; unresolvable `.invalid` host → classified failure, never success.
- Malformed host/port, non-HTTPS target, embedded URL credentials, CRLF/NUL/`:` injection in credentials → config errors.
- Secret redaction in Debug; destination fixture fails the test if proxy credentials are ever forwarded to it; first CONNECT must not carry preemptive auth.

One test fix during development: the timeout test initially used a 500 ms deadline that expired during TCP under parallel load; raised to 3 s (fixture sleeps 30 s, so the deadline still fires at `connect`).

## Limitations (honest status)
- **Fixture-verified only.** No live Windscribe connection was made or claimed. The phase-1 live gate is open, blocked on authorized credentials (below).
- A successful proof shows one HTTPS request through one proxy. It proves nothing about system routing, DNS, UDP/QUIC, IPv6, or other applications.
- CONNECT retry after 407 reuses the same TLS connection; a proxy that closes after 407 yields `proxy-protocol` (documented, not silently retried).
- The destination must return a bare IP body (api.ipify.org style). JSON endpoints fail as `invalid-ip` by design.
- Speedo static analysis completed (non-executing): Scorpion bundles sing-box (license file + version strings), APK adds HEV socks tunnel and strongSwan/OpenVPN, Iran split-routing lists present. Exact Scorpion config and credential source remain unknown. See research doc for hashes and inventory.
- sing-box v1.14.4 pinned and license-reviewed but not downloaded or used; GPL-3.0-or-later + name clause needs review before any bundling in phase 2+.

## Blocker: authorized Windscribe proxy credentials
Verified from pinned official sources: Windscribe documents **no non-browser HTTPS-proxy credential path** (SOCKS5 discontinued 2022; desktop API issues only OpenVPN/IKEv2 credentials; config generator has no proxy option). The extension's session-derived proxy credentials are public MIT source, but using them from a non-browser client is not a documented/supported interface, and AGENTS.md forbids impersonating a third-party client. We did not attempt login or call any Windscribe API.

Owner options (in order of preference):
1. Ask Windscribe support whether non-browser use of the HTTPS proxy with issued credentials is permitted, and if so how to obtain them.
2. If Windscribe issues/approves proxy credentials, run the live test below.
3. Meanwhile, the proof can be live-tested with any other HTTPS CONNECT proxy the owner is authorized to use — the CLI is provider-agnostic.

## Owner live-test instructions (when authorized credentials exist)
Safety: this program changes no routing, DNS, firewall, proxy settings, or certificates. It is safe to run alongside other software; for a clean measurement, disconnect Speedo first (owner controls VPN state; do not touch the Chrome extension login).

```powershell
# build once
cargo build --release
# run (credentials are prompted, not echoed, never stored)
.\target\release\windlab-proof.exe --proxy-host <provider-proxy-host> --proxy-port 443 --target-url https://api.ipify.org/
```

Record: timestamp, network type (no identifying details), the printed stage timings, exit IP, and exit code. Expected success: six `[ok]` stages and an exit IP belonging to the proxy provider, different from the local direct IP. Any `[fail]` line is a real, classified failure — do not interpret it as success. Compare against the official extension's behavior on the same network only as an observation, not a protocol-equivalence proof.

## Next decision
Owner input required to pass the phase-1 live gate. Do not advance to phase 2 (local proxy listener) until the live proof succeeds or the owner explicitly accepts a fixture-only milestone with a different authorized provider.