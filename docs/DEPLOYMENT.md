# Deployment guide

This client treats `src-tauri/resources/deployment.json` as a compile-time trust
boundary. Do not offer users a runtime server URL field and do not put an OIDC
client secret in this file. OpenBao is the confidential OIDC client; the desktop
application never receives the Kanidm secret.

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
- claim mappings for `email` and `preferred_username`
- a groups claim/policy mapping that gives only enrolled users certificate access

Keep the direct-callback confirmation page enabled.

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

For an email-address identity, enable only the matching bare-name behavior needed
by the role, disable arbitrary and wildcard names, cap TTL, and set the profile's
EKU. The mTLS role needs Client Authentication (`1.3.6.1.5.5.7.3.2`). Do not reuse
it for Office or code signing.

Before building the client, test with two accounts:

1. Alice can sign a CSR for Alice's mapped email.
2. Alice cannot sign a CSR for Bob's email.
3. A user outside the enrolled Kanidm group cannot call the sign endpoint.

If any negative test succeeds, stop. Fix OpenBao policy before distributing the
client.

## 3. Embed the deployment

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

## 4. Build and distribute

Build the per-user NSIS installer, then run `scripts/write-checksums.ps1`. Upload
both artifacts over already trusted HTTPS. Send the SHA-256 over a different
trusted channel and have the user compare it before bypassing SmartScreen.

Before creating a `v*` tag, run `scripts/assert-release-config.ps1`. The tagged
release workflow runs the same guard and refuses to publish placeholder builds.

Clicking **Run anyway** provides no publisher authentication. An unsigned build
must never describe itself as signed or verified.

Uninstalling intentionally leaves enrolled roots and personal certificates in
place. Users can remove a configured root explicitly in the application before
uninstalling.
