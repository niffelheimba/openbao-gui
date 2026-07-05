# Test and release gates

## Automated on every change

- Rust unit tests for configuration, URL construction, error redaction, and input
  injection boundaries
- release build of the Tauri application on Windows
- `cargo audit` vulnerability scan
- checksum and SBOM generation for release artifacts

## Milestone 0 — contract

Run against the real Kanidm and OpenBao environment. Record the OpenBao version,
auth mount accessor, redirect URL, mapped claims, policies, and PKI role output.
OIDC direct polling and the Alice/Bob negative issuance test must pass.

Before using the homelab, run `lab/Run-ContractTests.ps1` or dispatch the
**OpenBao contract lab** workflow. It uses the real OpenBao 2.5.5 binary and a
localhost mock provider to test direct callback, replay denial, claim mapping,
PKI templates, CNG CSRs, cross-identity denial, Windows user-store enrollment,
non-exportability, and loopback mTLS contracts.

## Milestone 1 — Windows shell

Build a preview installer with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-installer.ps1 `
  -Mode Preview
```

On clean Windows 10 22H2 x64 and current Windows 11 x64 VMs:

- install per-user without elevation;
- launch from Start, close to tray, restore, exit, and uninstall;
- verify a missing WebView2 runtime produces a prerequisite failure rather than
  silently downloading code;
- verify no startup-at-login entry is created.
- if using the placeholder deployment, verify the app clearly reports that root
  enrollment, sign-in, and certificate issuance are unavailable until
  `deployment.json` is configured.

## Milestone 2 — trust enrollment

- confirm internal HTTPS fails before enrollment and succeeds afterward;
- use **Check OpenBao** before trusting the root and verify the client refuses to
  connect until all embedded roots are installed;
- use **Check OpenBao** after enrollment and verify it reports the OpenBao server
  version over Windows-trusted HTTPS;
- compare subject, dates, and SHA-256 shown in the UI with the out-of-band values;
- install twice and verify idempotence;
- install a different root with the same subject and verify the client refuses to
  overwrite the conflict;
- remove trust explicitly and verify internal HTTPS fails again;
- uninstall and verify the root remains installed.

## Milestone 3 — authentication

Exercise success, denied Kanidm group, consent rejection, closed browser, five
minute timeout, cancellation, OpenBao restart, network loss, revoked token, and a
second poll using an already-consumed state/client nonce. Inspect application logs
and frontend IPC to verify that no token, nonce, or raw claim map appears.
Confirm the client waits for OpenBao's returned poll interval, treats
`slow_down` as a longer wait rather than a retry loop, and clears the local
session once its in-memory lease expires.

The OpenBao role must map both configured identity claims into auth metadata.
For the Northlake target, login must fail if `preferred_username` is absent or if
the immutable `sub` UUID is absent/blank, even before any certificate request is
attempted.

## Milestone 4 — mTLS v1 gate

- issue an mTLS certificate and confirm its email/CN, public-key match, Client
  Authentication EKU, chain, validity, and `CurrentUser\My` placement;
- when a profile has a SAN claim, confirm the returned certificate includes the
  expected SAN; when it has no SAN claim, confirm the request asks OpenBao not to
  copy a human username CN into SANs;
- verify the CNG key reports non-exportable;
- authenticate to a real mTLS service;
- cancel or break the network after CSR creation and verify the named OpenBao key
  container is removed;
- repeat the Alice/Bob impersonation test outside the GUI;
- verify the unsigned installer SHA-256 ceremony with a non-administrator user.

The disposable contract lab automates issuance, `CurrentUser` root/leaf
enrollment, key association, Client Authentication EKU, non-exportability,
Alice/Bob denial, and authentication to a loopback mTLS service. Production
OpenBao/Kanidm, interrupted-issuance, clean-VM, and installer-ceremony checks
remain manual release gates.

## Milestone 5 — Microsoft Office

Use a separate role and key with digitalSignature/contentCommitment and Microsoft
Document Signing EKU `1.3.6.1.4.1.311.10.3.12`. Sign a Word document and validate
it on another enrolled machine. Repeat with expired, revoked, incorrectly issued,
and untrusted certificates.

Client-side acceptance must reject a returned Office profile certificate that is
missing either `digitalSignature`, `contentCommitment`, or the Microsoft Document
Signing EKU before it is accepted into `CurrentUser\My`.

## Milestone 6 — internal code signing

Use a separate Code Signing role and key. Sign a test executable with SignTool.
It must verify on an enrolled machine and remain untrusted on a clean machine.
This does not provide SmartScreen reputation.

## Milestone 7 — YubiKey PIV-backed mTLS

Add a separate hardware-backed mTLS profile after the software-key v1 path is
stable. The profile uses the same OpenBao OIDC flow, but generates the private
key in a YubiKey PIV slot and sends only the CSR to OpenBao.

Contract checks:

- Kanidm maps `preferred_username=nicholas`, immutable `sub=<user UUID>`, and a
  `groups` claim containing `northlake_users` into OpenBao alias metadata;
- OpenBao attaches the YubiKey mTLS policy only to the authorized group/entity;
- the PKI role binds the requested certificate identity to alias metadata, so
  Nicholas can request `nicholas` and cannot request another username;
- if attestation is required, OpenBao or a pre-signing control verifies the PIV
  attestation chain before signing.

Client checks:

- detect no YubiKey, multiple YubiKeys, locked PIN, blocked PIN, missing PIV
  applet, unsupported algorithm, occupied slot, and removed device;
- show the selected slot, current certificate if present, and overwrite impact
  before generating a key;
- generate the key on-device, create the CSR from that slot, submit it to
  OpenBao, validate the returned certificate, and import it into the same slot;
- never print or log PINs, management keys, CSRs with sensitive names, raw claim
  maps, tokens, or private-key material;
- verify the certificate can authenticate to the real mTLS test service while
  the private key cannot be exported from the YubiKey;
- interruption after key generation but before certificate import leaves a clear
  recovery path and never silently overwrites a slot on retry.

Gate: an enrolled user can authenticate with the YubiKey-backed certificate on a
fresh Windows machine that has the homelab root installed, another user cannot
obtain the same identity, and slot overwrite/recovery behavior is documented and
tested with a sacrificial YubiKey.

## Milestone 8 — hardening and release operations

- run dependency audit, locked release build, SBOM generation, malware scanning,
  and checksum generation for every release candidate;
- verify release workflows refuse placeholder roots, unconfigured deployments,
  missing checksums, and unsigned-installer language that implies publisher
  authentication;
- test log files, crash reports, frontend IPC errors, and UI messages for token,
  nonce, PIN, raw claim, CSR, and private-key leakage;
- rehearse root rollover while the old HTTPS path is still valid;
- document backup/recovery, revocation, troubleshooting, manual upgrades, and
  the out-of-band SHA-256 ceremony.

Gate: a non-administrator can install the release candidate, verify the
out-of-band hash, enroll trust, authenticate, issue the intended certificate
profile, and uninstall without unexpected trust-store or key-store side effects.
