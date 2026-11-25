# Research and evidence register

## Observations supplied by owner (2026-11-25)
- Windscribe Pro account with TOTP 2FA; official Chrome extension already signed in.
- Chrome extension commonly connects without Speedo; desktop app does not on the same network.
- Speedo Scorpion works quickly, including desktop programs. UI describes web traffic on ports 80/443. This does not prove full UDP or all TCP ports work.
- WindLab 0.1.1 login helper returned `stage=account session/login; category=access denied; exit=9` while Speedo was connected. Exact HTTP status/root cause unconfirmed. Do not repeatedly retry login.

## Previous investigation leads (revalidate before relying on them)
Earlier conversation reports sing-box, HEV socks tunnel, HTTPS CONNECT, and Iran routing in Speedo; raw extraction artifacts and reproducible commands were not retained in this repository. Treat those claims as research leads, not independently verified findings. Upstream ownership, Scorpion's exact config, credential source and any extra obfuscation remain unknown.

Owner can provide local files (not in git):
- `Speedo_4.0.4_amd64.deb`
- `Speedo-4.0.4.msi`
- `Speedo-4.0.4-setup (2).exe`
- `Speedo-4.0.5.apk`

Perform non-executing analysis only: SHA-256 hashes, file inventory, package metadata, public dependency and license references, configuration schema indicators; record tool versions, file paths and confidence. Do not publish proprietary artifacts or secrets. Do not contact private Speedo endpoints or attempt to extract credentials.

## Public references
- [Official Windscribe MV3 extension](https://github.com/Windscribe/browser-extension-mv3) — README identifies HTTPS proxy; examine supported interfaces and license at pinned revision.
- [Official Windscribe desktop](https://github.com/Windscribe/Desktop-App) — compare architecture and officially supported authentication/protocols.
- [Windscribe desktop vs browser extension](https://vnm.windscribe.net/knowledge-base/articles/difference-between-desktop-app-and-browser-extension) — desktop tunnel and browser proxy differ.
- [sing-box](https://github.com/SagerNet/sing-box), [documentation](https://sing-box.sagernet.org/), [releases](https://github.com/SagerNet/sing-box/releases).
- [Foxhole upstream](https://github.com/Diercohen/foxhole-vpn), [owner's experimental fork PR](https://github.com/sanyzrn/foxhole-vpn/pull/1) — architectural reference, not project foundation. Earlier PR has not been built or live tested; do not blindly transplant.
- [Tauri](https://v2.tauri.app/).

## Research order
1. Determine whether the owner can obtain authorized HTTPS proxy credentials/endpoints through official supported methods. Confirm any restrictions on non-browser use. If not available, request provider support or stop this integration; don't bypass the boundary.
2. With approved data, compare TLS proxy connectivity on the same network, Speedo on vs off only when owner approves. Keep Chrome login intact.
3. Establish transport baseline and document only measured differences (connect latency, success rate, DNS behavior, upstream errors).
4. Investigate OS routing and performance after phase 1 succeeds. Avoid attributing success to Iranian network optimization without comparative evidence.

## Verified findings (2026-11-25, static source review only)

No Windscribe server was contacted, no login was attempted, no credentials were handled. All source reads were pinned to the commits below.

### Official MV3 extension — `Windscribe/browser-extension-mv3`
- Pinned commit `cfb29151334e38707d7cfffa3b52fc87c8de3f3f` (tag message "v4.3.1", 2026-10-22), default branch `public`. License: **MIT** (repo metadata + LICENSE file).
- Proxy model (verified in source): standard TLS-wrapped HTTP CONNECT proxy. PAC emits `HTTPS <host>:<port>;` chains; default port **443** (`src/utils/constants.ts`, `PROXY_PORT`); KB also documents 9443 as an option. Proxy hostnames are server-issued at runtime via `GET https://assets.windscribe.com/serverlist/chrome/<isPro>/<locHash>` — no hostname pattern is hardcoded in the source.
- Proxy credentials are **server-issued and session-derived, not the account password**: login `POST https://api.windscribe.com/Session` (with `2fa_code`, captcha, `session_type_id: 2`) returns `session_auth_hash`; `GET ServerCredentials` with `Authorization: Bearer <session_auth_hash>` returns base64 `{username, password}` (`src/api/endpoints.ts`, `src/state/slices/serverCredentials.ts`). Chrome supplies them via the 407 `webRequestAuthProvider` handler (`authRequiredHandler.ts`). Credentials are re-fetched on session polls; described in `docs/security.md` as ephemeral per-session.
- API failover: `api.windscribe.com` → `totallyacdn.com` → DoH TXT lookup of `dynamic-api-host.windscribe.com` via 1.1.1.1 (`src/api/sendRequest.ts`, `src/api/doh.ts`).
- 2FA: login error codes 1340/1341 switch the UI to 2FA; code resubmitted as `2fa_code`. Captcha is a slider puzzle with mouse-trail data.
- The repo ships build-time Node scripts (`scripts/login.js`, `scripts/getLocations.js`) that call the same API outside a browser, but **nothing in the repo endorses using the proxy or its credentials outside the extension**. The `client_auth_hash` secret ships in every build and is documented by Windscribe as "a soft replay-mitigation, not a real authentication factor" (`docs/security.md`).

### Official desktop — `Windscribe/Desktop-App` + `Windscribe/wsnet`
- Desktop-App pinned commit `b3f0f96718074fb3ea23eff891358bc81b70390d` ("v2.26.4", 2026-11-24). License: **GPL-2.0**. API client lives in `Windscribe/wsnet` tag **1.5.43** (tree `544a5365cf5123a73b344c69e7a393c81c8fb622`, GPL-2.0), fetched by `cmake/fetch_wsnet.cmake`.
- Complete endpoint inventory in `wsnet/src/api/serverapi/serverapi_requestsfactory.cpp`: `ServerCredentials` supports **`type=openvpn` and `type=ikev2` only**. There is **no HTTPS/SOCKS proxy-credential endpoint** anywhere in the desktop API surface.
- Desktop protocols (`src/client/client-common/types/protocol.h`): IKEV2, OPENVPN_UDP/TCP, STUNNEL, WSTUNNEL, WIREGUARD (+ AmneziaWG params). No HTTPS-proxy client protocol. "Proxy Gateway" in the desktop app is a **local LAN HTTP/SOCKS server**, not Windscribe-hosted proxy access.

### Knowledge base (fetched via windscribe.net mirror; windscribe.com TLS was reset from this network)
- `why-was-socks5-discontinued`: hosted SOCKS5 **discontinued 2022-04-30**; "We are a VPN provider, not a proxy provider."
- `what-is-the-proxy-gateway-feature-and-how-to-use-it`: Proxy Gateway is local/LAN-only.
- `getconfig/` → My Account config generator: **OpenVPN, IKEv2, WireGuard only**; no proxy option.
- `browser-extension-cannot-connect-(proxy-failure)`: extension proxy ports 443/9443; no documented credential export.

### Phase-0 verdict: explicit blocker
**No officially supported, documented path exists to obtain Windscribe HTTPS-proxy credentials for non-browser use.** The extension's mechanism is public MIT source and the owner's account is authorized, but (a) Windscribe documents no non-browser proxy credential issuance, (b) the desktop API deliberately issues only OpenVPN/IKEv2 credentials, and (c) whether the backend permits extension-style proxy credentials from other clients is untested and a provider-policy question. Per AGENTS.md we do not impersonate the extension or bypass this boundary. Next step is owner contact with Windscribe support, or testing the provider-agnostic proof with another authorized HTTPS proxy. The prior `WindLab 0.1.1` login denial (exit=9) remains unexplained; no login was retried.

### sing-box candidate engine (pinned, not downloaded)
- Release **v1.14.4** (published 2026-10-24, immutable release, tag target `testing`).
- Windows asset `sing-box-1.14.4-windows-amd64.zip`, 32,891,280 bytes, GitHub release digest `sha256:99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`.
- LICENSE (blob `175f35038fd936eb50439a4eb12d64501feb830c`): **GPL-3.0-or-later** plus an additional clause: no derivative work may use the name or imply association without prior consent. GitHub classifies it as "Other/NOASSERTION". Bundling/distribution obligations must be reviewed before phase 2+ ships any binary. Phase 1 does not use or download sing-box.

### Foxhole reference (metadata only)
- `Diercohen/foxhole-vpn`: MIT, TypeScript, built on **Firefox IP Protection** (a different provider/service), SOCKS5/HTTP + TUN + DoH. Architectural reference only; not a Windscribe access path and not a code source for WindLab. The owner's fork PR #1 remains unbuilt/untested as previously recorded.

### Speedo installers — static analysis (2026-11-25, non-executing)
Files found in `research-local/` (git-ignored; initial search of Downloads/Desktop/Documents missed them). Nothing was executed, no Speedo endpoint was contacted, no credentials were sought. Tools: `Get-FileHash` (SHA-256), Windows `tar.exe` (bsdtar) for ar/zip listing and extraction to a temp dir, WindowsInstaller COM read-only queries for MSI tables, `FileVersionInfo` and ASCII string scans for PE metadata. Artifacts stay out of git.

SHA-256 inventory:
| File | Bytes | SHA-256 |
| --- | --- | --- |
| Speedo-4.0.4-setup.exe | 24,672,891 | `bc0369eb13197a3fc986afa2e4113b364104581f4f9b92b37f30a1be1ba090cc` |
| Speedo-4.0.4.msi | 34,742,272 | `96146ca0355cef2a9f93f9ea4e4eb11ceb882453a31eaebc2e5c8adbef13d541` |
| Speedo-4.0.5.apk | 41,874,217 | `123e5f87233dbd6a8a887e30a5b10153836d2ef9250a77bf7242c2d6f15a51a1` |
| Speedo_4.0.4_amd64.deb | 31,995,360 | `c10eed6bbad48022959c00f026c751665a51d8f0a035b5dae38c6b1a65bc821e` |

Verified findings:
- **Scorpion bundles sing-box.** deb payload contains `usr/lib/Speedo/scorpion/speedo-scorpion` (81,338,597 bytes) alongside `LICENSE-sing-box.txt` whose text matches upstream sing-box's GPL-3.0-or-later + name/association clause. MSI ships `speedo-scorpion.exe` (81,987,584 bytes) and `LICENSE-sing-box.txt` (808 bytes). APK 4.0.5 ships `lib/arm64-v8a/libsingbox.so`. String scan of the Linux scorpion binary shows sing-box version markers from 1.6.0 through 1.14.0 (compatibility tables); the exact embedded version is **unconfirmed**.
- **HEV socks tunnel present**: `libhev-socks5-tunnel.so` in the APK (all ABIs). Consistent with a sing-box → SOCKS → TUN pipeline; not proven for Windows from these files alone.
- **Other engines**: APK also ships strongSwan/charon (IKEv2) and OpenVPN libs; deb depends on distro `openvpn`, `strongswan-swanctl`, `nftables`, `policykit-1`; MSI ships `openvpn.exe`, `ovpn-dco.sys` (two variants), `wintun.dll`, `tapctl.exe`, OpenSSL 3 DLLs, and a `speedo-helper.exe` (privilege helper pattern).
- **Iran split routing data**: `assets/iran/iran-domains.txt` + `iran-ipv4.txt` in APK; `iran-domains.txt` (843,428 bytes) + `iran-ipv4.txt` (27,386 bytes) in MSI. Provenance/license of these lists is unknown — do not copy without review.
- **UI**: APK assets include a Vite-built web UI (`assets/www/`) with Vazirmatn fonts (Persian), `bridge.js`; MSI `speedo.exe` is 6.4 MB (webview-style UI plausible, unconfirmed). deb description: "Speedo - bypass AI sanctions".
- MSI metadata: ProductName `Speedo`, ProductVersion `4.0.4`, Manufacturer `speedo`, UpgradeCode `{FCA983B8-2488-59B9-A47A-F1B86F15CF4C}`. setup.exe is an NSIS installer (Nullsoft strings), FileVersion 4.0.4. APK signed as `META-INF/SPEEDO.RSA` (certificate not analyzed).
- Confidence: high for file inventory/hashes and bundled-component presence; medium for pipeline architecture; the exact Scorpion config, credential source, and any extra obfuscation remain **unknown** (no config or credential material was extracted or sought).
