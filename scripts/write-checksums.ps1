[CmdletBinding()]
param(
    [string]$BundleDirectory
)

$ErrorActionPreference = "Stop"
if (-not $BundleDirectory) {
    $BundleDirectory = Join-Path $PSScriptRoot "..\target\release\bundle\nsis"
}
$resolved = (Resolve-Path -LiteralPath $BundleDirectory).Path
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $resolved.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Bundle directory must remain inside the workspace."
}

Get-ChildItem -LiteralPath $resolved -Filter *.exe -File | ForEach-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $line = "$hash  $($_.Name)`n"
    [IO.File]::WriteAllText("$($_.FullName).sha256", $line, [Text.UTF8Encoding]::new($false))
    Write-Host "$($_.Name): $hash"
}
