# Dependency and license policy

Project is private and no outbound distribution license has been selected. Preserve copyright and license notices for any reused code. Prefer independent implementation using public documentation; don't copy Speedo's proprietary UI/code or redistribute installers.

- sing-box upstream uses GPL terms; review exact pinned version's LICENSE and additional notices before bundling, linking, modifying or distributing. A separate executable does not automatically settle all licensing questions. Maintain corresponding source and required notices if distribution obligations apply.
- Windscribe source is public but each repository's actual license governs reuse; source availability and service authorization are separate. Verify terms for use of browser proxy beyond the browser.
- Foxhole upstream advertises MIT; retain notices if any code is reused. Reference alone does not make WindLab a fork.
- Verify Tauri, Rust crates, network drivers, rule lists, fonts and other assets individually. Record version, source URL, license, and integration type in a third-party manifest before release.

Do not choose a final project license or publish builds until reviewed. Avoid automatic copying of rule data without checking provenance and license. No legal conclusion about third-party service terms is implied by this document.

## Third-party manifest — phase 1 direct dependencies (2026-11-25)

Versions as resolved in the committed `Cargo.lock`; license strings read from each crate's published `Cargo.toml`. Integration type: static Rust linkage (crates.io). Transitive dependencies must be enumerated before any release.

| Crate | Version | License (SPDX expression) | Purpose |
| --- | --- | --- | --- |
| base64 | 0.22.1 | MIT OR Apache-2.0 | Basic auth encoding |
| clap | 4.6.10 | MIT OR Apache-2.0 | CLI parsing |
| httparse | 1.10.1 | MIT OR Apache-2.0 | HTTP response parsing |
| rpassword | 7.5.5 | Apache-2.0 | no-echo password prompt |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS (ring provider) |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | error types |
| tokio | 1.54.1 | MIT | async runtime |
| tokio-rustls | 0.26.6 | MIT OR Apache-2.0 | async TLS streams |
| url | 2.5.9 | MIT OR Apache-2.0 | target URL parsing |
| webpki-roots | 0.26.11 | CDLA-Permissive-2.0 | Mozilla root trust anchors |
| zeroize | 1.9.2 | Apache-2.0 OR MIT | secret zeroization |
| rcgen (dev only) | 0.13.2 | MIT OR Apache-2.0 | fixture certificates |

Referenced-but-not-bundled: sing-box v1.14.4 (GPL-3.0-or-later + additional name/association clause; see research doc), Windscribe Desktop-App/wsnet (GPL-2.0, read for research only), Windscribe MV3 extension (MIT, read for research only), Foxhole (MIT, metadata reference only). No code was copied from any of these into WindLab.
