# Product scope

## Goal
A lightweight, independently implemented desktop client that connects reliably where the official Windscribe desktop app fails, using an account the owner is entitled to use. The owner reports the official Chrome extension and Speedo's Scorpion mode usually work under those conditions. This observation is not a protocol equivalence proof.

## MVP
- Windows 11 x64 first; CLI proof, then small Tauri/Rust desktop UI.
- Authorized Windscribe HTTPS proxy as primary candidate; manual provider-issued credentials first, supported login with 2FA if available.
- Explicit local HTTP/SOCKS proxy; subsequently system-wide TUN after safety gates.
- Connection state, verified exit IP, server selection when supported, connect/disconnect, diagnostics, no misleading success messages.
- Later: user-selected split routing for domestic sites, reliable DNS, reconnect, measured fallback, secure credential storage, Persian/English UI.

## Non-goals
No new VPN protocol or server infrastructure, resale, account sharing, copying Speedo branding or proprietary code, subscription bypass, automatic CA installation, traffic interception, bundled browser credentials, or guaranteed all-protocol traffic through HTTP CONNECT. Firefox integration and Android are future work. No fake provider support if access is unavailable.
