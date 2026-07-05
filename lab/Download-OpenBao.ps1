[CmdletBinding()]
param(
    [string]$Version = "2.5.5",
    [string]$Destination
)

$ErrorActionPreference = "Stop"
if (-not $Destination) {
    $Destination = Join-Path $env:TEMP "openbao-gui-lab\openbao-$Version"
}
$archiveName = "bao_${Version}_Windows_x86_64.zip"
$release = "https://github.com/openbao/openbao/releases/download/v$Version"
$archive = Join-Path $Destination $archiveName
$checksums = Join-Path $Destination "checksums-windows.txt"
$executable = Join-Path $Destination "bao.exe"

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
if (-not (Test-Path -LiteralPath $executable)) {
    Invoke-WebRequest -UseBasicParsing -Uri "$release/$archiveName" -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri "$release/checksums-windows.txt" -OutFile $checksums
    $line = Get-Content -LiteralPath $checksums | Where-Object { $_ -match [regex]::Escape($archiveName) } | Select-Object -First 1
    if (-not $line -or $line -notmatch '^([0-9a-fA-F]{64})\s+') {
        throw "The official checksum file does not contain $archiveName."
    }
    $expected = $Matches[1].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "OpenBao archive checksum mismatch. Expected $expected; received $actual."
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force
}

if (-not (Test-Path -LiteralPath $executable)) {
    throw "OpenBao executable was not present after extraction."
}
Write-Output $executable
