# Security and privacy

## Threat model
Local unprivileged processes, other LAN clients, untrusted network/DNS, compromised downloads, accidental credential logging, wrong endpoint, route conflicts, and crashes. A VPN is not a guarantee of anonymity or availability. The upstream proxy provider remains trusted with traffic metadata; destination encryption remains end to end.

## Mandatory controls
- Explicit authorization for provider account; no 2FA bypass, Chrome profile extraction, third-party credentials or private Speedo API usage. Prefer supported provider login flow or issued proxy credentials.
- No credentials in shell history, arguments, environment dumps, logs, telemetry, crash reports, CI, screenshots or Git. Use secure local input; test exclusively with fake secrets. Environment variables are not a secure persistent store.
- Validate upstream TLS hostname, trust chain and target TLS; no insecure modes or custom root CA; no interception/MITM. Bind local proxy only to loopback; LAN sharing disabled.
- Pin releases, verify hashes/signatures from trusted metadata, reject missing integrity evidence for distributed engine. Document supply-chain risks and dependency licenses.
- Explicit direct-routing policy: default no direct fallback for protected traffic; explain that proxy-only does not protect unconfigured applications. Block unsupported UDP and validate IPv6, DNS, QUIC behavior before any system-wide claim.
- No telemetry or remote configuration by default. Logs local, minimal, sanitized, bounded and deletable; domain/IP logging opt-in.
- Before elevated actions: owner approval, network snapshot, restoration strategy and documented recovery. Avoid altering other VPNs or system trust; test in disposable Windows environment first.
- On crash/cancel, stop owned processes and restore owned resources; for global mode prove recovery on next launch. Any kill-switch guarantee requires OS-level tests, not UI state.

## Stop conditions
Stop on unexpected credential prompts, account restrictions, repeated auth denial, active VPN conflicts, TLS validation errors, or failed rollback. Report sanitized error class and reproduction steps. No automatic escalation or risky workaround.
