[CmdletBinding()]
param(
    [switch]$IncludeYubiKey
)

$ErrorActionPreference = "Stop"
$failed = $false

function Write-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Ok,
        [string]$Detail,
        [string]$Hint
    )

    if ($Ok) {
        Write-Host "[OK]   $Name $Detail"
    } else {
        Write-Host "[MISS] $Name $Detail" -ForegroundColor Yellow
        if ($Hint) {
            Write-Host "       $Hint" -ForegroundColor DarkYellow
        }
        $script:failed = $true
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Check `
    -Name "Rust cargo" `
    -Ok ([bool]$cargo) `
    -Detail $(if ($cargo) { "at $($cargo.Source)" } else { "" }) `
    -Hint "Install Rust stable from https://rustup.rs/, then reopen PowerShell."

if ($cargo) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $cargoVersion = ((& $cargo.Source --version) 2>$null) -join " "
    $cargoVersionExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    Write-Host "       $cargoVersion"

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $tauriVersionOutput = (& $cargo.Source tauri --version) 2>&1
    $tauriExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    $tauriVersion = ($tauriVersionOutput |
        Where-Object { $_ -match "tauri-cli" } |
        Select-Object -Last 1)
    if (-not $tauriVersion) {
        $tauriVersion = ($tauriVersionOutput -join " ")
    }
    Write-Check `
        -Name "Tauri CLI" `
        -Ok ($tauriExitCode -eq 0) `
        -Detail $(if ($tauriExitCode -eq 0) { $tauriVersion } else { "" }) `
        -Hint "Run: cargo install tauri-cli --version '^2' --locked"
}

$webViewRuntime = @(
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKLM:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKLM:\Software\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F1E7B518-7D45-4121-8007-6CF64395D7D4}",
    "HKLM:\Software\Microsoft\EdgeUpdate\Clients\{F1E7B518-7D45-4121-8007-6CF64395D7D4}",
    "HKLM:\Software\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F1E7B518-7D45-4121-8007-6CF64395D7D4}",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
    "${env:ProgramFiles}\Microsoft\EdgeWebView\Application\msedgewebview2.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
Write-Check `
    -Name "WebView2 Runtime" `
    -Ok ([bool]$webViewRuntime) `
    -Detail $(if ($webViewRuntime) { "detected" } else { "" }) `
    -Hint "Install the Evergreen WebView2 Runtime. The app installer intentionally does not download it."

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vcTools = $false
if (Test-Path -LiteralPath $vsWhere) {
    $installPath = & $vsWhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $vcTools = -not [string]::IsNullOrWhiteSpace($installPath)
}
Write-Check `
    -Name "MSVC C++ build tools" `
    -Ok $vcTools `
    -Detail $(if ($vcTools) { "detected" } else { "" }) `
    -Hint "Install Visual Studio Build Tools with the Desktop development with C++ workload."

if ($IncludeYubiKey) {
    $ykman = Get-Command ykman -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ykman) {
        $ykman = Get-ChildItem -LiteralPath "${env:ProgramFiles}\Yubico" -Recurse -Filter ykman.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    $ykmanPath = if ($ykman -and $ykman.PSObject.Properties.Name -contains "Source") {
        $ykman.Source
    } elseif ($ykman) {
        $ykman.FullName
    } else {
        $null
    }
    Write-Check `
        -Name "YubiKey Manager CLI" `
        -Ok ([bool]$ykman) `
        -Detail $(if ($ykmanPath) { "at $ykmanPath" } else { "" }) `
        -Hint "Install YubiKey Manager CLI or add ykman.exe to PATH before testing the hardware-key milestone."
}

if ($failed) {
    exit 1
}

Write-Host ""
Write-Host "All requested prerequisites are present."
