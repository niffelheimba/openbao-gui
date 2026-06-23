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

Write-Host "Release configuration accepted for $($config.deployment_name)."
