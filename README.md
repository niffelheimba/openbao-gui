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
- per-user OpenBao endpoint/auth settings, constrained to HTTPS and the embedded
  trust policy

The checked-in deployment file is deliberately unconfigured. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before building an installer.

## Development

Prerequisites:

- Rust stable with the MSVC Windows target
- Microsoft C++ Build Tools
- WebView2 Runtime
- Tauri CLI 2 (`cargo install tauri-cli --version '^2' --locked`)

Check the local machine before building:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/check-prereqs.ps1
```

Add `-IncludeYubiKey` when preparing for the later hardware-backed-key milestone.

```powershell
cargo test --workspace
cargo tauri dev
```

Create an unsigned per-user NSIS installer and its checksum:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/build-installer.ps1 -Mode Preview
```

Use `-Online` the first time on a fresh machine if Cargo has not cached the
project dependencies yet.

`Preview` mode is for smoke-testing the installer, tray behavior, settings UI,
and unconfigured-state messaging. It may build with the placeholder deployment.
Use `-Mode Release` only after `deployment.json` contains the real homelab root
and OpenBao profiles; release mode runs the configuration guard before building.

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
- YubiKey PIV-backed mTLS issuance through an installed `ykman`, including slot
  inventory, expired-certificate removal, and renewal using an existing hardware
  key
- Local loopback mTLS test-site scripts for checking whether Windows/browser TLS
  can present the issued client certificate
- CI tests, dependency audit, SBOM/checksum jobs, and operator documentation

Production Kanidm OIDC, clean-VM installation, Office signing, SignTool, and
YubiKey PIV-backed mTLS acceptance tests require the target homelab, Windows
applications, and hardware; their exact gates are documented in
[docs/TESTING.md](docs/TESTING.md).

The [disposable contract lab](lab/README.md) can exercise real OpenBao OIDC/PKI
behavior locally or through the manual **OpenBao contract lab** GitHub workflow
without using the production deployment file. It covers direct OIDC polling,
replay and cross-identity denial, Windows trust/leaf enrollment, CNG
non-exportability, and an actual loopback mTLS handshake.

YubiKey support does not bundle YubiKey Manager. Install `ykman` separately; the
client uses it to generate PIV keys, create CSRs, import signed certificates, and
inspect/remove certificates from common PIV slots.

For a quick browser/client-certificate smoke test, start the local mTLS site:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/Start-MtlsTestSite.ps1
```

Open the reported `https://localhost:<port>/` URL and choose the issued mTLS
certificate when Windows asks. Stop and clean up the temporary localhost trust
certificate afterward:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./scripts/Stop-MtlsTestSite.ps1
```
