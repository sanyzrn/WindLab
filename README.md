# WindLab

Independent personal Windows VPN client, prioritizing reliable connectivity on Iranian networks using the owner's authorized Windscribe account.

Status (2026-11-25): phase-1 CLI proof implemented and fixture-verified (`windlab-proof`, 26 local tests). **Live Windscribe connectivity is not yet proven**: official sources document no non-browser HTTPS-proxy credential path (see [research](docs/03-RESEARCH.md) and [phase report](docs/08-PHASE1-REPORT.md)). No GUI, no TUN, no OS network changes.

## Start here
- [AGENTS.md](AGENTS.md): mandatory engineering instructions
- [Product scope](docs/01-PRODUCT.md)
- [Architecture](docs/02-ARCHITECTURE.md)
- [Research and evidence](docs/03-RESEARCH.md)
- [Security and privacy](docs/04-SECURITY.md)
- [Roadmap and acceptance](docs/05-ROADMAP.md)
- [Windows test plan](docs/06-WINDOWS-TESTS.md)
- [Dependencies and licensing](docs/07-LICENSES.md)
- [Phase 0/1 report](docs/08-PHASE1-REPORT.md)
- [Engineering handoff prompt](AGENT_PROMPT.md)

First milestone: prove an independently authorized HTTPS proxy connection works with Speedo disconnected. No UI or global routing required for that milestone. Do not treat a successful connection to a proxy as evidence of a working full-device VPN.

No affiliation with Windscribe, Mozilla, Speedo, Foxhole or SagerNet. No commercial distribution is planned. Project licensing is intentionally undecided pending dependency review.
