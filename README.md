# OpenBao Certificate Client

A lightweight Windows tray client for enrolling a homelab root CA and requesting
user certificates from OpenBao after Kanidm OIDC authentication.

The client is intentionally narrow:

- Windows 10/11 x64, per-user installation
- Tauri 2 with a Rust backend and dependency-free HTML/CSS/JavaScript UI
- direct OpenBao HTTP API access (no `bao.exe`)
- Current User `Root` and `My` certificate stores
- in-memory OpenBao sessions
- locally generated, non-exportable RSA-3072 CNG keys

The checked-in deployment file is deliberately unconfigured. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before building an installer.

## Development

Prerequisites:

- Rust stable with the MSVC Windows target
- Microsoft C++ Build Tools
- WebView2 Runtime
- Tauri CLI 2 (`cargo install tauri-cli --version '^2' --locked`)

```powershell
cargo test --workspace
cargo tauri dev
```

Create an unsigned per-user NSIS installer and its checksum:

```powershell
cargo tauri build --bundles nsis
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/write-checksums.ps1
```

An unsigned installer is not authenticated by clicking **Run anyway**. Send the
generated SHA-256 to users over a separate trusted channel and require them to
compare it before running the installer.

Tags matching `v*` run the release workflow. It refuses to publish while the
embedded deployment remains unconfigured or contains placeholder trust material.

## Current implementation status

- Tray shell and minimal status UI
- Strict embedded deployment configuration validation
- Root CA inspection, idempotent Current User installation, and explicit removal
- OpenBao direct-callback OIDC start/poll/cancel/logout flow
- OpenBao 2.5.5 minimum-version enforcement and renewable in-memory sessions
- Tokens retained only in Rust memory and redacted from diagnostics
- Authenticated root rollover preview with explicit fingerprint approval
- CNG-backed CSR generation and PKI signing/install pipeline using Windows
  `certreq.exe`; keys are non-exportable and use named containers for cleanup
- Leaf identity, EKU, public-key, validity, and cryptographic chain validation
  back to an embedded root before Windows accepts a certificate
- Current User certificate inventory with expiry display and explicit replacement
  confirmation
- CI tests, dependency audit, SBOM/checksum jobs, and operator documentation

Real OIDC, certificate issuance, Office signing, and mTLS acceptance tests require
the target homelab and Windows applications; their exact gates are documented in
[docs/TESTING.md](docs/TESTING.md).
