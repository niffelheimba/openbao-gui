# Disposable OpenBao contract lab

This lab exercises the real OpenBao 2.5.5 OIDC and PKI APIs without Docker and
without reading or changing `src-tauri/resources/deployment.json`.

It provides:

- a small Rust OIDC provider with discovery, PKCE, UserInfo, JWKS, and RS256 ID
  tokens;
- a checksum-verified official OpenBao Windows binary running in dev mode;
- an ephemeral PKI root and identity-templated mTLS role;
- a direct callback/poll login as `alice@example.test`;
- rejection of a replayed state/client-nonce poll;
- locally generated, non-exportable CNG CSRs;
- a positive Alice issuance and a negative Alice-requesting-Bob assertion;
- temporary root enrollment in `CurrentUser\\Root` before leaf acceptance;
- temporary acceptance into `CurrentUser\\My`, private-key association and
  client-auth EKU checks, plus an attempted private-key export that must fail.
- a loopback TLS service that requires and validates Alice's client certificate.

All server state, logs, CSRs, and the lab root are written beneath
`%TEMP%\openbao-gui-contract-lab`. Named CNG key containers are deleted in the
script's `finally` block, and both services are stopped unless `-KeepProcesses`
is supplied. Temporary root and leaf certificates accepted into the Windows
user stores are also removed before the script exits.

Run on Windows from a developer shell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./lab/Run-ContractTests.ps1
```

The first run downloads OpenBao from its official GitHub release and verifies
the archive against `checksums-windows.txt`. Pass `-BaoPath` to use an already
verified `bao.exe` instead.

The mock provider is test infrastructure only. It authenticates every valid
authorization request as Alice and must never be exposed beyond localhost.
