[CmdletBinding()]
param(
    [string]$Configuration
)

$ErrorActionPreference = "Stop"
if (-not $Configuration) {
    $Configuration = Join-Path $PSScriptRoot "..\src-tauri\resources\deployment.json"
}
$config = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json

if ($config.schema_version -ne 1) { throw "Release configuration must use schema_version 1." }
if (-not $config.configured) { throw "Refusing to release an unconfigured client." }
if ($config.openbao.address -notmatch '^https://') { throw "OpenBao address must use HTTPS." }
if ($config.openbao.address -match 'example\.invalid') { throw "OpenBao address is still a placeholder." }
if (@($config.roots).Count -lt 1) { throw "At least one root certificate is required." }
if (@($config.profiles).Count -lt 1) { throw "At least one certificate profile is required." }

foreach ($root in @($config.roots)) {
    if ($root.pem -match 'REPLACE_WITH' -or $root.sha256 -match 'REPLACE_WITH') {
        throw "Root '$($root.id)' still contains placeholder material."
    }
    if ($root.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Root '$($root.id)' must have a lowercase SHA-256 fingerprint."
    }
}

$requiredEkus = @{
    'mtls' = '1.3.6.1.5.5.7.3.2'
    'document-signing' = '1.3.6.1.4.1.311.10.3.12'
    'code-signing' = '1.3.6.1.5.5.7.3.3'
}

$profileIds = @{}
foreach ($profile in @($config.profiles)) {
    if (-not $profile.id -or $profile.id -notmatch '^[A-Za-z0-9_-]+$') {
        throw "Profile has an invalid id '$($profile.id)'."
    }
    if ($profileIds.ContainsKey($profile.id)) {
        throw "Duplicate profile id '$($profile.id)'."
    }
    $profileIds[$profile.id] = $true
    if (-not $requiredEkus.ContainsKey($profile.purpose)) {
        throw "Profile '$($profile.id)' has unsupported purpose '$($profile.purpose)'."
    }
    $required = $requiredEkus[$profile.purpose]
    if (@($profile.expected_eku_oids) -notcontains $required) {
        throw "Profile '$($profile.id)' is missing required EKU $required."
    }
    if ($profile.destination_store -ne 'My' -or $profile.key_algorithm -ne 'rsa-3072') {
        throw "Profile '$($profile.id)' must use CurrentUser\My and rsa-3072."
    }
}

Write-Host "Release configuration accepted for $($config.deployment_name)."
