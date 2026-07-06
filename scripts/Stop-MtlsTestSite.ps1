[CmdletBinding()]
param(
    [string]$StatePath = (Join-Path $env:TEMP "openbao-gui-mtls-test\state.json")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $StatePath)) {
    Write-Host "No mTLS test site state file found at $StatePath."
    return
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json

if ($state.processId) {
    $process = Get-Process -Id $state.processId -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $state.processId -Force
        Write-Host "Stopped mTLS test site process $($state.processId)."
    }
}

if ($state.serverThumbprint) {
    foreach ($storeName in @("My", "Root")) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            [Security.Cryptography.X509Certificates.StoreName]::$storeName,
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $matches = @($store.Certificates | Where-Object Thumbprint -EQ $state.serverThumbprint)
            foreach ($certificate in $matches) {
                $store.Remove($certificate)
                $certificate.Dispose()
            }
            if ($matches.Count -gt 0) {
                Write-Host "Removed temporary localhost certificate from CurrentUser\$storeName."
            }
        } finally {
            $store.Close()
        }
    }
}

Remove-Item -LiteralPath $StatePath -Force
Write-Host "mTLS test site stopped."
