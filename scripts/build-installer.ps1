[CmdletBinding()]
param(
    [ValidateSet("Preview", "Release")]
    [string]$Mode = "Preview",
    [switch]$Online,
    [switch]$SkipTests,
    [switch]$SkipChecksum
)

$ErrorActionPreference = "Stop"

function Resolve-RequiredCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$InstallHint
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        throw "$Name was not found on PATH. $InstallHint"
    }
    return $command.Source
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    Write-Host ">> $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE."
    }
}

$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Push-Location $workspace
try {
    $cargo = Resolve-RequiredCommand -Name "cargo" -InstallHint "Install Rust stable with the MSVC Windows target from https://rustup.rs/."

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

    if (-not $webViewRuntime) {
        Write-Warning "Microsoft Edge WebView2 Runtime was not detected. The app requires the installed runtime because the installer intentionally does not bundle or download it."
    }

    Invoke-Checked -FilePath $cargo -Arguments @("tauri", "--version")

    if ($Mode -eq "Release") {
        Write-Host "Running release configuration guard."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\assert-release-config.ps1"
        if ($LASTEXITCODE -ne 0) {
            throw "Release configuration guard failed."
        }
    } else {
        Write-Warning "Preview mode allows an unconfigured deployment. Use it for tray/UI/installer smoke tests only."
    }

    Invoke-Checked -FilePath $cargo -Arguments @("fmt", "--all", "--", "--check")

    if (-not $SkipTests) {
        $testArguments = @("test", "--workspace", "--locked")
        if (-not $Online) {
            $testArguments += "--offline"
        } else {
            Write-Warning "Online mode allows Cargo to download missing dependencies into the user Cargo cache."
        }
        Invoke-Checked -FilePath $cargo -Arguments $testArguments
    } else {
        Write-Warning "Skipping tests by request."
    }

    Invoke-Checked -FilePath $cargo -Arguments @("tauri", "build", "--bundles", "nsis")

    if (-not $SkipChecksum) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\write-checksums.ps1"
        if ($LASTEXITCODE -ne 0) {
            throw "Checksum generation failed."
        }
    }

    $bundleDirectory = Join-Path $workspace "target\release\bundle\nsis"
    Write-Host ""
    Write-Host "Installer artifacts:"
    Get-ChildItem -LiteralPath $bundleDirectory -File |
        Where-Object { $_.Extension -in ".exe", ".sha256" } |
        Sort-Object Name |
        ForEach-Object { Write-Host "  $($_.FullName)" }

    if ($Mode -eq "Preview") {
        Write-Host ""
        Write-Warning "This is not a publishable production build unless deployment.json has been configured with the real root and OpenBao profiles."
    }
} finally {
    Pop-Location
}
