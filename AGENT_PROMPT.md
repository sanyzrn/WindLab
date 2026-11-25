# Local Windows agent — first mission

Read AGENTS.md and all documentation in this repository. Build WindLab from scratch as a lightweight, independent Windows client, using sing-box as the candidate external engine and the owner's authorized Windscribe service. Start with research and a minimal CLI connectivity proof; do not build a GUI or enable TUN yet.

Review official Windscribe sources, the Foxhole reference, and the supplied Speedo installers using static analysis only. Validate prior assumptions and find a supported path to proxy endpoints and credentials without touching the active browser session or bypassing authentication. Preserve 2FA. Use only owner-authorized credentials and provider-permitted access. If a required capability is unsupported, report the blocker rather than invent a workaround.

Implement a secure, reproducible HTTPS proxy proof and local fixture tests. Prioritize verified connectivity on Iranian networks, clear diagnostics, secret safety, simplicity, and measurable results. Do not change Windows routing, DNS, firewall, trust store or existing VPN without explicit owner approval. Be creative within these constraints; use better evidence-based approaches when appropriate.

Work on `feature/windscribe-proof`. Run relevant tests, document evidence and limitations, commit and push, and open a draft PR. Stop at the phase-1 acceptance gate if live validation requires owner input. Provide exact instructions for the owner to test with Speedo disconnected when safe. Do not merge or publish.
