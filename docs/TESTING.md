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

## Milestone 1 — Windows shell

On clean Windows 10 22H2 x64 and current Windows 11 x64 VMs:

- install per-user without elevation;
- launch from Start, close to tray, restore, exit, and uninstall;
- verify a missing WebView2 runtime produces a prerequisite failure rather than
  silently downloading code;
- verify no startup-at-login entry is created.

## Milestone 2 — trust enrollment

- confirm internal HTTPS fails before enrollment and succeeds afterward;
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

## Milestone 4 — mTLS v1 gate

- issue an mTLS certificate and confirm its email/CN, public-key match, Client
  Authentication EKU, chain, validity, and `CurrentUser\My` placement;
- verify the CNG key reports non-exportable;
- authenticate to a real mTLS service;
- cancel or break the network after CSR creation and verify the named OpenBao key
  container is removed;
- repeat the Alice/Bob impersonation test outside the GUI;
- verify the unsigned installer SHA-256 ceremony with a non-administrator user.

## Milestone 5 — Microsoft Office

Use a separate role and key with digitalSignature/contentCommitment and Microsoft
Document Signing EKU `1.3.6.1.4.1.311.10.3.12`. Sign a Word document and validate
it on another enrolled machine. Repeat with expired, revoked, incorrectly issued,
and untrusted certificates.

## Milestone 6 — internal code signing

Use a separate Code Signing role and key. Sign a test executable with SignTool.
It must verify on an enrolled machine and remain untrusted on a clean machine.
This does not provide SmartScreen reputation.
