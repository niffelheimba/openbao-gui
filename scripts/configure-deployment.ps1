[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DeploymentName,
    [Parameter(Mandatory)][string]$OpenBaoAddress,
    [Parameter(Mandatory)][string]$RootCertificate,
    [string]$Namespace,
    [string]$AuthMount = "oidc",
    [string]$OidcRole = "desktop-certificates",
    [string]$PkiMount = "pki-users",
    [string]$MtlsRole = "user-mtls",
    [string]$IdentityDisplayClaim = "preferred_username",
    [string]$IdentitySubjectClaim = "sub",
    [string]$MtlsSubjectClaim = "email",
    [AllowEmptyString()][string]$MtlsSanClaim = "email",
    [string]$RootId = "homelab-root",
    [string]$RootRefreshPath = "pki-root/ca/pem",
    [switch]$IncludeOffice,
    [switch]$IncludeCodeSigning,
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\src-tauri\resources\deployment.json"
}
foreach ($claim in @($IdentityDisplayClaim, $IdentitySubjectClaim, $MtlsSubjectClaim)) {
    if ($claim -notmatch '^[A-Za-z0-9_.-]+$') {
        throw "Claim names must contain only letters, numbers, underscore, dash, or dot."
    }
}
if ($MtlsSanClaim -and $MtlsSanClaim -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "Claim names must contain only letters, numbers, underscore, dash, or dot."
}
$rootPath = (Resolve-Path -LiteralPath $RootCertificate).Path
$raw = [IO.File]::ReadAllBytes($rootPath)
$text = [Text.Encoding]::ASCII.GetString($raw)
if ($text -match '-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----') {
    $raw = [Convert]::FromBase64String(($Matches.body -replace '\s', ''))
}
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
try {
    $basicConstraints = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
    if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority) {
        throw "RootCertificate must contain a CA certificate with CA basic constraints."
    }
    $der = $certificate.RawData
    $fingerprint = ($certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256) |
        ForEach-Object { $_.ToString('x2') }) -join ''
    $base64 = [Convert]::ToBase64String($der)
    $lines = for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $base64.Substring($offset, [Math]::Min(64, $base64.Length - $offset))
    }
    $pem = "-----BEGIN CERTIFICATE-----`n$($lines -join "`n")`n-----END CERTIFICATE-----`n"

    $profiles = [Collections.ArrayList]::new()
    $null = $profiles.Add([ordered]@{
        id = 'user-mtls'; label = 'User mTLS'; description = 'Client authentication for homelab services'
        purpose = 'mtls'; pki_mount = $PkiMount; pki_role = $MtlsRole
        subject_claim = $MtlsSubjectClaim; san_claim = if ($MtlsSanClaim) { $MtlsSanClaim } else { $null }; destination_store = 'My'
        key_algorithm = 'rsa-3072'; expected_eku_oids = @('1.3.6.1.5.5.7.3.2')
    })
    if ($IncludeOffice) {
        $null = $profiles.Add([ordered]@{
            id = 'office-document-signing'; label = 'Office document signing'; description = 'Personal signing certificate for Microsoft Office'
            purpose = 'document-signing'; pki_mount = $PkiMount; pki_role = 'office-document-signing'
            subject_claim = 'email'; san_claim = $null; destination_store = 'My'
            key_algorithm = 'rsa-3072'; expected_eku_oids = @('1.3.6.1.4.1.311.10.3.12')
        })
    }
    if ($IncludeCodeSigning) {
        $null = $profiles.Add([ordered]@{
            id = 'internal-code-signing'; label = 'Internal code signing'; description = 'Code signing trusted only by enrolled homelab machines'
            purpose = 'code-signing'; pki_mount = $PkiMount; pki_role = 'internal-code-signing'
            subject_claim = 'email'; san_claim = $null; destination_store = 'My'
            key_algorithm = 'rsa-3072'; expected_eku_oids = @('1.3.6.1.5.5.7.3.3')
        })
    }

    $configuration = [ordered]@{
        schema_version = 1
        configured = $true
        deployment_name = $DeploymentName
        openbao = [ordered]@{
            address = $OpenBaoAddress.TrimEnd('/')
            namespace = if ($Namespace) { $Namespace } else { $null }
            auth_mount = $AuthMount
            oidc_role = $OidcRole
            minimum_version = '2.5.5'
        }
        identity = [ordered]@{ display_claim = $IdentityDisplayClaim; subject_claim = $IdentitySubjectClaim }
        roots = @([ordered]@{
            id = $RootId
            pem = $pem
            sha256 = $fingerprint
            refresh_path = if ($RootRefreshPath) { $RootRefreshPath } else { $null }
        })
        profiles = @($profiles)
    }
    $json = ConvertTo-Json -InputObject $configuration -Depth 12
    $output = [IO.Path]::GetFullPath($OutputPath)
    [IO.File]::WriteAllText($output, "$json`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Configured $DeploymentName with root SHA-256 $fingerprint"
    Write-Host "Wrote $output"
} finally {
    $certificate.Dispose()
}
