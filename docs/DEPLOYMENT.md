# Deployment guide

This client treats the roots and certificate profiles in
`src-tauri/resources/deployment.json` as a compile-time trust boundary. Users may
override the OpenBao HTTPS origin, namespace, auth mount, and OIDC role from the
Server Settings panel. The override does not add a root or weaken Windows TLS
validation, so the selected server must chain to an embedded root that the user
has explicitly enrolled.

Do not put an OIDC client secret in the deployment or per-user settings. OpenBao
is the confidential OIDC client; the desktop application never receives the
Kanidm secret.

There is intentionally no identity-provider field in the desktop client.
OpenBao's configured auth mount and role select the provider, validate its
tokens, map claims, and return the browser authorization URL. For the usual
deployment, users only change the OpenBao URL; auth mount, role, and namespace
remain the embedded defaults under **Advanced OpenBao settings**.

## 1. Establish the OpenBao/Kanidm contract

Target OpenBao 2.5.5 or newer. In Kanidm, create a dedicated confidential OAuth2
client for OpenBao, enable the `openid`, `profile`, `email`, and required group
scopes, and configure this exact redirect URI:

```text
https://BAO_HOST:8200/v1/auth/oidc/oidc/callback
```

The repeated `oidc` is intentional: the first is the auth mount and the second is
the callback endpoint. Change the first segment if the auth mount has another
name. Use Kanidm's client-specific discovery URL:

```text
https://IDM_HOST/oauth2/openid/OPENBAO_CLIENT_ID
```

Configure OpenBao with the Kanidm client ID and secret, then create a role using
server-direct callbacks. The exact CLI flags can change between OpenBao releases;
confirm them with `bao read auth/oidc/role/desktop-certificates` after applying.
The role must include:

- `role_type=oidc`
- `callback_mode=direct`
- the callback URL above in `allowed_redirect_uris`
- claim mappings for `sub`, `email`, `preferred_username`, and any certificate
  identity claim used by a profile
- a groups claim/policy mapping that gives only enrolled users certificate access

Keep the direct-callback confirmation page enabled.

For the Northlake homelab target, the intended OIDC contract is:

- `preferred_username=nicholas` for the human-readable certificate identity when
  the profile is configured that way;
- `sub=<immutable user UUID>` as the durable OpenBao entity/alias anchor;
- `groups` contains `northlake_users` before any certificate policy is attached.

The desktop client may display `preferred_username` and may request a CSR with
that value as the configured profile common name. OpenBao must still authorize
the request from the immutable subject and group membership; a renamed username
must not accidentally grant access to another entity.

## 2. Enforce certificate identity on the server

The GUI is not an authorization boundary. A user can call the OpenBao API without
it, so the PKI role must reject a request for another user's identity.

Use `allowed_domains_template=true` and bind `allowed_domains` to metadata on the
OIDC identity alias. Obtain the OIDC auth mount accessor with:

```text
bao auth list -detailed
```

An illustrative template is:

```text
{{identity.entity.aliases.AUTH_MOUNT_ACCESSOR.metadata.email}}
```

For a username identity such as `nicholas`, bind `allowed_domains` or the
appropriate OpenBao PKI name restriction to:

```text
{{identity.entity.aliases.AUTH_MOUNT_ACCESSOR.metadata.preferred_username}}
```

For durable policy decisions, use the OpenBao entity produced from the OIDC
alias whose metadata includes the immutable `sub` UUID, and attach certificate
policies only for identities whose mapped `groups` include `northlake_users`.
Enable only the matching bare-name behavior needed by the role, disable
arbitrary and wildcard names, cap TTL, and set the profile's EKU. The mTLS role
needs Client Authentication (`1.3.6.1.5.5.7.3.2`). Do not reuse it for Office or
code signing.

Before building the client, test with two accounts:

1. Alice can sign a CSR for Alice's mapped email.
2. Alice cannot sign a CSR for Bob's email.
3. A user outside the enrolled Kanidm group cannot call the sign endpoint.

If any negative test succeeds, stop. Fix OpenBao policy before distributing the
client.

## 3. Split PKI mounts by trust domain

Use separate PKI mounts when certificate families have different revocation
authority, risk, or operators. The desktop app's user mTLS profile should not
share a mount with internal server TLS or code-signing certificates, because
OpenBao's raw PKI revoke endpoint is scoped at the mount path.

The recommended Northlake layout is:

```text
pki_user_mtls
pki_internal_server_tls
pki_code_signing        # optional, only when code signing is deployed
```

For the desktop app, grant the user policy only the user-mTLS mount:

```hcl
path "pki_user_mtls/sign/northlake-users" {
  capabilities = ["update"]
}

path "pki_user_mtls/revoke" {
  capabilities = ["update"]
}

path "pki_user_mtls/cert/*" {
  capabilities = ["read"]
}
```

Do not grant the desktop user policy `update` on
`pki_internal_server_tls/revoke`. Server certificates should be issued and
revoked by infrastructure automation or an operator policy, not by the user
certificate client.

If renaming an existing mount, remember that previously issued certificates
contain their original AIA and CRL URLs. Prefer doing this before production
issuance, or keep the old path reachable until old certificates expire.

Example mount setup:

```powershell
bao secrets move pki_intermediate pki_user_mtls
bao write pki_user_mtls/config/urls `
  issuing_certificates="https://secrets.cloud.northlake.dev/v1/pki_user_mtls/ca" `
  crl_distribution_points="https://secrets.cloud.northlake.dev/v1/pki_user_mtls/crl"
bao write pki_user_mtls/config/crl `
  expiry="720h" `
  auto_rebuild=true `
  auto_rebuild_grace_period="24h" `
  enable_delta=false
bao write pki_user_mtls/roles/northlake-users `
  allow_any_name=true `
  allow_bare_domains=false `
  allow_glob_domains=false `
  allow_ip_sans=false `
  allow_localhost=false `
  allow_subdomains=false `
  allow_wildcard_certificates=false `
  client_flag=true `
  server_flag=false `
  code_signing_flag=false `
  email_protection_flag=false `
  ext_key_usage=ClientAuth `
  key_usage=DigitalSignature `
  key_type=any `
  key_bits=0 `
  country=US `
  organization=Northlake `
  ou="Northlake Users" `
  require_cn=true `
  cn_validations=email,hostname `
  enforce_hostnames=false `
  use_csr_common_name=true `
  use_csr_sans=false `
  ttl=720h `
  max_ttl=2160h `
  not_before_duration=5m `
  generate_lease=false `
  no_store=false

bao secrets enable `
  -path=pki_internal_server_tls `
  -description="Northlake internal server TLS PKI" `
  -max-lease-ttl=87600h `
  pki
bao write pki_internal_server_tls/config/urls `
  issuing_certificates="https://secrets.cloud.northlake.dev/v1/pki_internal_server_tls/ca" `
  crl_distribution_points="https://secrets.cloud.northlake.dev/v1/pki_internal_server_tls/crl"
bao write pki_internal_server_tls/config/crl `
  expiry="720h" `
  auto_rebuild=true `
  auto_rebuild_grace_period="24h" `
  enable_delta=false
```

The server-TLS mount still needs its own issuing CA before it can sign server
leaf certificates. Generate a server-TLS intermediate CSR under
`pki_internal_server_tls`, sign it with the offline/root CA, then import the
signed intermediate back into that mount.

```powershell
bao write -format=json `
  pki_internal_server_tls/intermediate/generate/internal `
  common_name="Northlake Internal Server TLS Issuing CA 01" `
  key_type=rsa `
  key_bits=4096 `
  ttl=131400h
```

After signing the CSR with the root CA:

```powershell
bao write pki_internal_server_tls/intermediate/set-signed `
  certificate=@".\northlake-internal-server-tls-issuing-ca-01.crt.pem"
```

The initial internal server role should be narrow. For Northlake, the
`internal-home-server` role allows only subdomains below `home.northlake.dev`,
sets Server Authentication, and does not allow client-auth, code-signing,
localhost, IP SANs, or bare-domain issuance:

```powershell
bao write pki_internal_server_tls/roles/internal-home-server `
  allowed_domains=home.northlake.dev `
  allow_subdomains=true `
  allow_bare_domains=false `
  allow_wildcard_certificates=true `
  allow_ip_sans=false `
  allow_localhost=false `
  server_flag=true `
  client_flag=false `
  code_signing_flag=false `
  email_protection_flag=false `
  ext_key_usage=ServerAuth `
  key_usage=DigitalSignature,KeyEncipherment `
  key_type=rsa `
  key_bits=2048 `
  ttl=720h `
  max_ttl=2160h `
  require_cn=true `
  enforce_hostnames=true `
  generate_lease=false `
  no_store=false
```

## 4. Embed the deployment

For an mTLS-only first build, generate the deployment file from your CA
certificate instead of editing JSON manually:

```powershell
.\scripts\configure-deployment.ps1 `
  -DeploymentName "My Homelab" `
  -OpenBaoAddress "https://bao.home.example:8200" `
  -RootCertificate ".\homelab-root.cer" `
  -PkiMount "pki_user_mtls" `
  -MtlsRole "user-mtls"
```

The script accepts DER or PEM, verifies that it is a CA certificate, calculates
the DER SHA-256, and creates the default mTLS profile. Add `-IncludeOffice` or
`-IncludeCodeSigning` only after those dedicated OpenBao roles exist.

An Office document-signing role must be separate from mTLS. Configure it to allow
only the mapped user identity, issue RSA leaf certificates, and produce:

- Key Usage: `DigitalSignature` and `ContentCommitment`;
- EKU OID: `1.3.6.1.4.1.311.10.3.12`;
- no Client Authentication or Code Signing EKU.

The client also validates those returned certificate fields before accepting the
certificate into `CurrentUser\My`.

To request mTLS certificates using the OIDC preferred username as the certificate
common name while keeping the immutable OIDC subject as the identity anchor:

```powershell
.\scripts\configure-deployment.ps1 `
  -DeploymentName "Northlake Homelab" `
  -OpenBaoAddress "https://bao.northlake.example:8200" `
  -RootCertificate ".\northlake-root.cer" `
  -IdentityDisplayClaim "preferred_username" `
  -IdentitySubjectClaim "sub" `
  -MtlsSubjectClaim "preferred_username" `
  -MtlsSanClaim ""
```

This produces a CSR common name such as `nicholas`. The OpenBao role must reject
that same request unless the authenticated entity maps to the matching immutable
`sub` and an authorized group such as `northlake_users`. Because this profile has
no SAN claim, the client asks OpenBao to exclude the CN from SANs; that keeps a
human username from being treated as a DNS or email SAN.

Copy `src-tauri/resources/deployment.example.json` over `deployment.json` and set:

- the canonical HTTPS OpenBao address;
- the auth mount and OIDC role;
- a stable ID and complete PEM for every initial root;
- the lowercase SHA-256 of each certificate's DER bytes;
- one profile per PKI role and intended use.

Generate a root fingerprint with PowerShell:

```powershell
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new("root.cer")
($cert.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256) | ForEach-Object ToString x2) -join ""
```

Set `configured` to `true`. `cargo test --workspace` fails configuration tests if
the PEM and fingerprint disagree, the address is not HTTPS, IDs are unsafe, or a
v1 profile does not use the Current User Personal store and RSA-3072.

The embedded OpenBao values become defaults. A user can change the server origin,
namespace, auth mount, and OIDC role in the app while signed out. Settings are
stored as non-secret `server.json` in the application's per-user configuration
directory and apply after exiting from the tray and reopening the app. The new
direct callback URL must also be present in that OpenBao OIDC role's
`allowed_redirect_uris`. Use **Use embedded defaults** to remove the override.

## 5. Build and distribute

For a local smoke-test installer before the real homelab deployment is embedded,
build in preview mode:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-installer.ps1 `
  -Mode Preview `
  -Online
```

Preview mode is useful for testing installer launch, tray restore, server
settings, WebView2 prerequisite behavior, and the warning shown by an
unconfigured build. It is not a production artifact. Use `-Online` on the first
build of a fresh machine so Cargo can populate its dependency cache; omit it for
repeatable offline rebuilds once the cache is warm.

For a distributable homelab build, configure `deployment.json`, then build in
release mode:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-installer.ps1 `
  -Mode Release
```

Release mode runs `scripts/assert-release-config.ps1`, Rust formatting checks,
the offline Rust test suite, the Tauri NSIS build, and checksum generation.
Upload both artifacts over already trusted HTTPS. Send the SHA-256 over a
different trusted channel and have the user compare it before bypassing
SmartScreen.

Before creating a `v*` tag, run `scripts/assert-release-config.ps1`. The tagged
release workflow runs the same guard and refuses to publish placeholder builds.

Clicking **Run anyway** provides no publisher authentication. An unsigned build
must never describe itself as signed or verified.

Uninstalling intentionally leaves enrolled roots and personal certificates in
place. Users can remove a configured root explicitly in the application before
uninstalling.

## 6. Hardware-backed keys with YubiKey PIV

YubiKey support is planned after the v1 software-key release. Treat it as a
separate certificate profile family, not as a transparent replacement for the
Current User CNG profile.

Recommended direction:

- require YubiKey Manager CLI (`ykman`) or a native PIV library as an external
  prerequisite for the first hardware-key milestone;
- do not bundle `ykman` in the application installer until updater, provenance,
  and licensing/release verification are designed;
- generate the key inside a selected PIV slot, create the CSR from that slot,
  send the CSR to OpenBao, then import the returned certificate back into the
  same slot;
- prefer a dedicated mTLS slot such as `9a` or a documented configurable slot,
  and never overwrite a slot without an explicit fingerprint/subject preview;
- optionally collect and submit YubiKey PIV attestation later, so OpenBao can
  distinguish keys genuinely generated on-device from imported private keys.

The CLI shape is viable: Yubico documents `ykman piv keys generate` as generating
the private key on the YubiKey, `ykman piv certificates request` as creating a CSR
from an existing slot key, `ykman piv certificates import` for placing the signed
certificate into the slot, and `ykman piv keys attest` for proof that a key was
generated on the YubiKey.
