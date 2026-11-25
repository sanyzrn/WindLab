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
