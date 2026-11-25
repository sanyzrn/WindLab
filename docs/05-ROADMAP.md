# Roadmap and acceptance gates

| Phase | Scope | Exit criteria |
| --- | --- | --- |
| 0 | Research and feasibility | Evidence log, provider-approved credential path or explicit blocker, pinned engine and license review |
| 1 | Minimal CLI proof | Config validation, upstream and destination TLS, actual proxied HTTPS/IP response, no false success; manual tests with Speedo off if owner approves |
| 2 | Local proxy | Loopback-only SOCKS/HTTP, auth failures distinguishable, bounded retries/cancellation, no unsupported UDP fallback, local fixture tests |
| 3 | Windows TUN | Owner-approved Windows tests: DNS/IPv6/UDP policy, no protected traffic leaks, conflict detection, rollback on failure/crash, no orphan routes/processes |
| 4 | Reliability | Compare repeated connections, p50/p95 time and failure classes across available networks; implement only evidence-backed fallback; optional Iran split routing |
| 5 | Desktop UI | Compact Tauri GUI, provider/region selection, secure storage, state accuracy, EN/FA RTL, tray, accessibility, clear limitations |
| 6 | Release readiness | Signed/verified dependencies, CI, reproducible installer, third-party notices, rollback, live Windows test report |
| Later | Other platforms/providers | Android and Firefox only after independent feasibility/licensing assessment |

Do not advance a gate when real credentials, network access, or owner consent are missing. Mark fixture-only verification separately. A successful live test is the first deliverable; UI can wait. If provider access is unsupported, deliver a reusable mock/authorized manual HTTPS proof without claiming Windscribe works.

Every phase report: scope, commits, source evidence, tests executed and results, limitations, next decision. No fabricated pass counts. Open a draft PR for review.
