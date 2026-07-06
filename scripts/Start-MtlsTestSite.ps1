[CmdletBinding()]
param(
    [int]$Port = 0,
    [string]$StatePath = (Join-Path $env:TEMP "openbao-gui-mtls-test\state.json")
)

$ErrorActionPreference = "Stop"

function New-RandomPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Add-CertificateToRootStore {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::Root,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($Certificate)
    } finally {
        $store.Close()
    }
}

$stateDirectory = Split-Path -Parent $StatePath
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null

if (Test-Path -LiteralPath $StatePath) {
    throw "An mTLS test site state file already exists at $StatePath. Run scripts\Stop-MtlsTestSite.ps1 first."
}

if ($Port -eq 0) {
    $Port = New-RandomPort
}

$serverScript = Join-Path $stateDirectory "mtls-test-server.ps1"
$logPath = Join-Path $stateDirectory "server.log"

$serverCertificate = New-SelfSignedCertificate `
    -Subject "CN=localhost" `
    -DnsName "localhost" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyExportPolicy NonExportable `
    -KeyUsage DigitalSignature,KeyEncipherment `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

Add-CertificateToRootStore -Certificate $serverCertificate

@'
param(
    [Parameter(Mandatory = $true)][int]$Port,
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [Parameter(Mandatory = $true)][string]$ReadyPath
)

$ErrorActionPreference = "Stop"
$listener = $null
$serverCertificate = $null

function Get-ClientAuthStatus {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.37") {
            $formatted = $extension.Format($false)
            if ($formatted -match "1\.3\.6\.1\.5\.5\.7\.3\.2|Client Authentication") {
                return "present"
            }
            return "missing"
        }
    }
    return "not listed"
}

function Write-HttpResponse {
    param(
        [Net.Security.SslStream]$Stream,
        [string]$Body,
        [string]$ContentType = "text/html; charset=utf-8"
    )
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $header = "HTTP/1.1 200 OK`r`nContent-Type: $ContentType`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

try {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $serverCertificate = $store.Certificates | Where-Object Thumbprint -EQ $Thumbprint | Select-Object -First 1
        if (-not $serverCertificate -or -not $serverCertificate.HasPrivateKey) {
            throw "The localhost server certificate was not found with its private key."
        }
    } finally {
        $store.Close()
    }

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    [IO.File]::WriteAllText($ReadyPath, "https://localhost:$Port/", [Text.UTF8Encoding]::new($false))

    while ($true) {
        $tcp = $listener.AcceptTcpClient()
        try {
            $chainErrorText = "not evaluated"
            $callback = {
                param($sender, $certificate, $chain, $errors)
                $script:LastPolicyErrors = $errors.ToString()
                $script:LastChainStatus = if ($chain) {
                    ($chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join "; "
                } else {
                    ""
                }
                return $null -ne $certificate
            }
            $tls = [Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
            try {
                $tls.AuthenticateAsServer(
                    $serverCertificate,
                    $true,
                    [Security.Authentication.SslProtocols]::Tls12,
                    $false
                )
                $remote = [Security.Cryptography.X509Certificates.X509Certificate2]::new($tls.RemoteCertificate)
                try {
                    $buffer = [byte[]]::new(4096)
                    $null = $tls.Read($buffer, 0, $buffer.Length)

                    $clientAuthStatus = Get-ClientAuthStatus -Certificate $remote
                    $policyErrors = if ($script:LastPolicyErrors) { $script:LastPolicyErrors } else { "None" }
                    $chainStatus = if ($script:LastChainStatus) { $script:LastChainStatus } else { "None reported" }
                    $now = [DateTimeOffset]::Now.ToString("u")
                    $body = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>OpenBao mTLS test</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 2rem; line-height: 1.45; color: #17221d; }
    code { overflow-wrap: anywhere; }
    .ok { color: #0c7b51; font-weight: 700; }
    .warn { color: #9b6416; font-weight: 700; }
    dl { display: grid; grid-template-columns: 12rem 1fr; gap: .45rem 1rem; }
    dt { font-weight: 700; }
  </style>
</head>
<body>
  <h1 class="ok">mTLS handshake succeeded</h1>
  <p>Your browser or Windows TLS stack presented a client certificate to this local test server.</p>
  <dl>
    <dt>Subject</dt><dd><code>$([Net.WebUtility]::HtmlEncode($remote.Subject))</code></dd>
    <dt>Issuer</dt><dd><code>$([Net.WebUtility]::HtmlEncode($remote.Issuer))</code></dd>
    <dt>Thumbprint</dt><dd><code>$($remote.Thumbprint)</code></dd>
    <dt>Valid until</dt><dd>$($remote.NotAfter.ToString("u"))</dd>
    <dt>Client auth EKU</dt><dd>$clientAuthStatus</dd>
    <dt>TLS policy errors</dt><dd><code>$([Net.WebUtility]::HtmlEncode($policyErrors))</code></dd>
    <dt>Chain status</dt><dd><code>$([Net.WebUtility]::HtmlEncode($chainStatus))</code></dd>
    <dt>Checked at</dt><dd>$now</dd>
  </dl>
  <p class="warn">If chain status is not clean, the certificate was usable for mTLS but Windows did not build a fully trusted chain for the local server process.</p>
</body>
</html>
"@
                    Write-HttpResponse -Stream $tls -Body $body
                } finally {
                    $remote.Dispose()
                }
            } finally {
                $tls.Dispose()
            }
        } catch {
            Add-Content -LiteralPath (Join-Path (Split-Path -Parent $ReadyPath) "server.log") -Value "$(Get-Date -Format o) $($_.Exception.Message)"
        } finally {
            $tcp.Dispose()
        }
    }
} finally {
    if ($listener) { $listener.Stop() }
}
'@ | Set-Content -LiteralPath $serverScript -Encoding UTF8

$readyPath = Join-Path $stateDirectory "ready.txt"
$process = Start-Process `
    -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $serverScript, "-Port", $Port, "-Thumbprint", $serverCertificate.Thumbprint, "-ReadyPath", $readyPath) `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $stateDirectory "server.out.log") `
    -RedirectStandardError (Join-Path $stateDirectory "server.err.log") `
    -PassThru

$deadline = [DateTime]::UtcNow.AddSeconds(10)
while (-not (Test-Path -LiteralPath $readyPath)) {
    if ($process.HasExited) {
        throw "The mTLS test server exited early. Check $logPath and $(Join-Path $stateDirectory "server.err.log")."
    }
    if ([DateTime]::UtcNow -gt $deadline) {
        throw "Timed out waiting for the mTLS test server to start."
    }
    Start-Sleep -Milliseconds 100
}

$state = [pscustomobject]@{
    port = $Port
    url = "https://localhost:$Port/"
    processId = $process.Id
    serverThumbprint = $serverCertificate.Thumbprint
    statePath = $StatePath
    stateDirectory = $stateDirectory
    startedAt = [DateTimeOffset]::Now.ToString("o")
}
$state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding UTF8

Write-Host "mTLS test site is running:"
Write-Host "  https://localhost:$Port/"
Write-Host ""
Write-Host "Open that URL in Edge/Chrome. Pick your OpenBao/YubiKey client certificate if Windows asks."
Write-Host "Stop it with:"
Write-Host "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Stop-MtlsTestSite.ps1"
