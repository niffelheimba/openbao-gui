[CmdletBinding()]
param(
    [string]$BaoPath,
    [switch]$KeepProcesses
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$runId = [Guid]::NewGuid().ToString('N')
$labRoot = Join-Path $env:TEMP "openbao-gui-contract-lab\$runId"
$logs = Join-Path $labRoot "logs"
$requests = Join-Path $labRoot "requests"
New-Item -ItemType Directory -Force -Path $logs,$requests | Out-Null

if (-not $BaoPath) {
    $BaoPath = & (Join-Path $PSScriptRoot "Download-OpenBao.ps1")
}
$BaoPath = (Resolve-Path -LiteralPath $BaoPath).Path

$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $workspace "target" }
$mockOidc = Join-Path $targetRoot "debug\openbao-mock-oidc.exe"
$cargo = Get-Command cargo -ErrorAction Stop
& $cargo.Source build -p openbao-mock-oidc
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $mockOidc)) {
    throw "The mock OIDC provider did not build successfully at $mockOidc."
}

$mockProcess = $null
$baoProcess = $null
$mtlsJob = $null
$keyContainers = [Collections.Generic.List[string]]::new()
$installedThumbprints = [Collections.Generic.List[string]]::new()
$installedRootThumbprints = [Collections.Generic.List[string]]::new()
$script:requestNumber = 0

function Wait-Http([string]$Uri, [int]$Seconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try { Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2 | Out-Null; return }
        catch { Start-Sleep -Milliseconds 250 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Uri."
}

function Invoke-BaoApi {
    param([string]$Method, [string]$Path, [object]$Body, [string]$Token = "lab-root")
    $script:requestNumber++
    $arguments = [Collections.Generic.List[string]]::new()
    @("--silent", "--show-error", "--max-time", "15", "--request", $Method.ToUpperInvariant()) | ForEach-Object { $arguments.Add($_) }
    if ($Token) { $arguments.Add("--header"); $arguments.Add("X-Vault-Token: $Token") }
    if ($null -ne $Body) {
        $requestFile = Join-Path $requests ("api-{0:D3}.json" -f $script:requestNumber)
        $json = ConvertTo-Json -InputObject $Body -Depth 12 -Compress
        [IO.File]::WriteAllText($requestFile, $json, [Text.UTF8Encoding]::new($false))
        $arguments.Add("--header"); $arguments.Add("Content-Type: application/json")
        $arguments.Add("--data-binary"); $arguments.Add("@$requestFile")
    }
    $arguments.Add("--write-out"); $arguments.Add("`n%{http_code}")
    $arguments.Add("http://127.0.0.1:18200/v1/$Path")
    $lines = @(& "$env:SystemRoot\System32\curl.exe" @arguments)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 1) { throw "OpenBao request $Method $Path failed at the transport layer." }
    $status = [int]$lines[-1]
    $payload = if ($lines.Count -gt 1) { $lines[0..($lines.Count - 2)] -join "`n" } else { "" }
    if ($status -lt 200 -or $status -ge 300) { throw "OpenBao request $Method $Path returned HTTP $status`: $payload" }
    if (-not $payload) { return $null }
    $payload | ConvertFrom-Json
}

function New-LabCsr([string]$Identity, [string]$Name) {
    $container = "OpenBao-Lab-$Name-$([Guid]::NewGuid().ToString('N'))"
    $keyContainers.Add($container) | Out-Null
    $inf = Join-Path $requests "$Name.inf"
    $csr = Join-Path $requests "$Name.req"
    @"
[Version]
Signature=`"`$Windows NT`$`"

[NewRequest]
Subject=`"CN=$Identity`"
Exportable=FALSE
KeyLength=3072
KeyAlgorithm=RSA
HashAlgorithm=sha256
KeySpec=0
ProviderName=`"Microsoft Software Key Storage Provider`"
ProviderType=0
MachineKeySet=FALSE
RequestType=PKCS10
KeyContainer=`"$container`"
KeyUsage=0xa0
Silent=TRUE
"@ | Set-Content -LiteralPath $inf -Encoding ascii
    & "$env:SystemRoot\System32\certreq.exe" -new -q -user $inf $csr | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows failed to create the $Name CSR." }
    Get-Content -LiteralPath $csr -Raw
}

function Convert-CertificatePemToDer([string]$CertificatePem) {
    $match = [Text.RegularExpressions.Regex]::Match(
        $CertificatePem,
        "-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----"
    )
    if (-not $match.Success) { throw "OpenBao returned an invalid PEM certificate." }
    # Unary comma prevents PowerShell from streaming a byte array one byte at a time.
    return ,([Convert]::FromBase64String(($match.Groups['body'].Value -replace '\s', '')))
}

function Install-LabRoot([string]$CertificatePem) {
    [byte[]]$rootDer = Convert-CertificatePemToDer $CertificatePem
    $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rootDer)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::Root,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($root)
        $installedRootThumbprints.Add($root.Thumbprint) | Out-Null
        return $root.Thumbprint
    } finally {
        $store.Close()
        $root.Dispose()
    }
}

function Install-And-TestLabCertificate([string]$CertificatePem) {
    [byte[]]$der = Convert-CertificatePemToDer $CertificatePem
    $certificatePath = Join-Path $requests "alice-issued.cer"
    [IO.File]::WriteAllBytes($certificatePath, $der)
    $issued = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)

    & "$env:SystemRoot\System32\certreq.exe" -accept -q -user $certificatePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows failed to accept Alice's issued certificate." }

    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::My,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $installed = $store.Certificates | Where-Object Thumbprint -EQ $issued.Thumbprint | Select-Object -First 1
        if (-not $installed) { throw "The accepted certificate was not found in CurrentUser\\My." }
        $installedThumbprints.Add($installed.Thumbprint) | Out-Null
        if (-not $installed.HasPrivateKey) { throw "The accepted certificate was not associated with its CNG key." }
        if ($installed.Subject -notmatch 'alice@example\.test') { throw "The installed certificate identity is not Alice." }

        $clientAuth = $false
        foreach ($extension in $installed.Extensions) {
            if ($extension.Oid.Value -eq '2.5.29.37' -and $extension.Format($false) -match '1\.3\.6\.1\.5\.5\.7\.3\.2|Client Authentication') {
                $clientAuth = $true
            }
        }
        if (-not $clientAuth) { throw "The installed certificate lacks the TLS client-authentication EKU." }

        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($installed)
        if (-not $rsa) { throw "The installed certificate does not expose its RSA CNG key." }
        try {
            $exportSucceeded = $false
            try {
                $rsa.ExportParameters($true) | Out-Null
                $exportSucceeded = $true
            } catch [Security.Cryptography.CryptographicException] {
                # Expected: the Microsoft Software KSP key was created non-exportable.
            }
            if ($exportSucceeded) { throw "Security regression: Alice's private key was exportable." }
        } finally {
            $rsa.Dispose()
        }
        return $installed.Thumbprint
    } finally {
        $store.Close()
        $issued.Dispose()
    }
}

function Install-LabServerCertificate([string]$CertificatePem) {
    [byte[]]$der = Convert-CertificatePemToDer $CertificatePem
    $certificatePath = Join-Path $requests "server-issued.cer"
    [IO.File]::WriteAllBytes($certificatePath, $der)
    $issued = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    & "$env:SystemRoot\System32\certreq.exe" -accept -q -user $certificatePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows failed to accept the lab mTLS server certificate." }

    $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $installed = $store.Certificates | Where-Object Thumbprint -EQ $issued.Thumbprint | Select-Object -First 1
        if (-not $installed -or -not $installed.HasPrivateKey) {
            throw "The lab mTLS server certificate was not associated with its CNG key."
        }
        $installedThumbprints.Add($installed.Thumbprint) | Out-Null
        return $installed.Thumbprint
    } finally {
        $store.Close()
        $issued.Dispose()
    }
}

function Test-LabMtls([string]$ServerThumbprint, [string]$ClientThumbprint) {
    $port = Get-Random -Minimum 20000 -Maximum 40000
    $script:mtlsJob = Start-Job -ArgumentList $port,$ServerThumbprint -ScriptBlock {
        param($Port, $Thumbprint)
        $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        $listener = $null
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $serverCertificate = $store.Certificates | Where-Object Thumbprint -EQ $Thumbprint | Select-Object -First 1
            if (-not $serverCertificate) { throw "mTLS server certificate was not found." }
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
            $listener.Start()
            Write-Output 'READY'
            $tcp = $listener.AcceptTcpClient()
            try {
                $callback = { param($sender, $certificate, $chain, $errors) $errors -eq [Net.Security.SslPolicyErrors]::None }
                $tls = [Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
                try {
                    $tls.AuthenticateAsServer(
                        $serverCertificate,
                        $true,
                        [Security.Authentication.SslProtocols]::Tls12,
                        $false
                    )
                    $remote = [Security.Cryptography.X509Certificates.X509Certificate2]::new($tls.RemoteCertificate)
                    if ($remote.Subject -notmatch 'alice@example\.test') { throw "Unexpected mTLS client identity." }
                    $buffer = [byte[]]::new(4096)
                    $null = $tls.Read($buffer, 0, $buffer.Length)
                    $body = 'mTLS alice accepted'
                    $response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                    $bytes = [Text.Encoding]::ASCII.GetBytes($response)
                    $tls.Write($bytes, 0, $bytes.Length)
                    $tls.Flush()
                    Write-Output "CLIENT=$($remote.Subject)"
                    $remote.Dispose()
                } finally {
                    $tls.Dispose()
                }
            } finally {
                $tcp.Dispose()
            }
        } finally {
            if ($listener) { $listener.Stop() }
            $store.Close()
        }
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $jobOutput = @(Receive-Job -Job $script:mtlsJob -Keep)
        if ($jobOutput -contains 'READY') { break }
        if ($script:mtlsJob.State -eq 'Failed') { throw "The local mTLS service failed to start: $($script:mtlsJob.ChildJobs[0].JobStateInfo.Reason)" }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($jobOutput -notcontains 'READY') { throw "Timed out starting the local mTLS service." }

    $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $clientCertificate = $store.Certificates | Where-Object Thumbprint -EQ $ClientThumbprint | Select-Object -First 1
        $response = Invoke-WebRequest -UseBasicParsing -Uri "https://localhost:$port/" -Certificate $clientCertificate -TimeoutSec 15
        if ($response.StatusCode -ne 200 -or $response.Content -ne 'mTLS alice accepted') {
            throw "The local mTLS service did not accept Alice's certificate."
        }
    } finally {
        $store.Close()
    }
    Wait-Job -Job $script:mtlsJob -Timeout 15 | Out-Null
    $finalOutput = @(Receive-Job -Job $script:mtlsJob -Keep)
    if (-not ($finalOutput -match 'CLIENT=.*alice@example\.test')) {
        throw "The local mTLS service did not observe Alice's client identity."
    }
}

try {
    $env:MOCK_OIDC_ADDR = "127.0.0.1:19090"
    $env:MOCK_OIDC_ISSUER = "http://127.0.0.1:19090"
    $mockProcess = Start-Process -FilePath $mockOidc -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logs "oidc.out.log") `
        -RedirectStandardError (Join-Path $logs "oidc.err.log")
    Wait-Http "http://127.0.0.1:19090/health"

    $baoProcess = Start-Process -FilePath $BaoPath -WindowStyle Hidden -PassThru `
        -ArgumentList @("server", "-dev", "-dev-root-token-id=lab-root", "-dev-listen-address=127.0.0.1:18200") `
        -RedirectStandardOutput (Join-Path $logs "bao.out.log") `
        -RedirectStandardError (Join-Path $logs "bao.err.log")
    Wait-Http "http://127.0.0.1:18200/v1/sys/health"

    Invoke-BaoApi Post "sys/auth/oidc" @{ type = "jwt" } | Out-Null
    Invoke-BaoApi Post "auth/oidc/config" @{
        oidc_discovery_url = "http://127.0.0.1:19090"
        oidc_client_id = "openbao-lab"
        oidc_client_secret = "openbao-lab-secret"
        default_role = "desktop-certificates"
    } | Out-Null
    Invoke-BaoApi Post "sys/policies/acl/lab-user" @{
        policy = @'
path "pki-users/sign/user-mtls" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
'@
    } | Out-Null
    Invoke-BaoApi Post "auth/oidc/role/desktop-certificates" @{
        role_type = "oidc"
        user_claim = "sub"
        allowed_redirect_uris = @("http://127.0.0.1:18200/v1/auth/oidc/oidc/callback")
        callback_mode = "direct"
        oidc_disable_confirmation = $true
        oidc_scopes = @("openid", "profile", "email", "groups")
        claim_mappings = @{ email = "email"; preferred_username = "preferred_username" }
        token_policies = @("lab-user")
        token_ttl = "15m"
    } | Out-Null

    Invoke-BaoApi Post "sys/mounts/pki-users" @{ type = "pki"; config = @{ max_lease_ttl = "8760h" } } | Out-Null
    $root = Invoke-BaoApi Post "pki-users/root/generate/internal" @{
        common_name = "OpenBao GUI Contract Lab Root"
        ttl = "8760h"
        key_type = "rsa"
        key_bits = 3072
    }
    $rootThumbprint = Install-LabRoot $root.data.certificate
    $auths = Invoke-BaoApi Get "sys/auth" $null
    $accessor = $auths.data.'oidc/'.accessor
    if (-not $accessor) { throw "OIDC auth mount accessor was not returned." }
    $identityTemplate = "{{identity.entity.aliases.$accessor.metadata.email}}"
    Invoke-BaoApi Post "pki-users/roles/user-mtls" @{
        allowed_domains = @($identityTemplate)
        allowed_domains_template = $true
        allow_bare_domains = $true
        allow_subdomains = $false
        allow_glob_domains = $false
        allow_any_name = $false
        allow_wildcard_certificates = $false
        enforce_hostnames = $true
        client_flag = $true
        server_flag = $false
        code_signing_flag = $false
        email_protection_flag = $false
        key_usage = @("DigitalSignature", "KeyEncipherment")
        ttl = "15m"
    } | Out-Null
    Invoke-BaoApi Post "pki-users/roles/lab-server" @{
        allowed_domains = @('localhost')
        allow_bare_domains = $true
        allow_subdomains = $false
        allow_any_name = $false
        enforce_hostnames = $true
        client_flag = $false
        server_flag = $true
        key_usage = @('DigitalSignature', 'KeyEncipherment')
        ttl = '15m'
    } | Out-Null

    $clientNonce = [Guid]::NewGuid().ToString('N')
    $challenge = Invoke-BaoApi Post "auth/oidc/oidc/auth_url" @{
        role = "desktop-certificates"
        redirect_uri = "http://127.0.0.1:18200/v1/auth/oidc/oidc/callback"
        client_nonce = $clientNonce
    } ""
    if (-not $challenge.data.auth_url -or -not $challenge.data.state) {
        throw "OpenBao did not return a direct OIDC challenge."
    }
    & "$env:SystemRoot\System32\curl.exe" --silent --show-error --fail --location --max-redirs 10 --max-time 15 $challenge.data.auth_url | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "The test OIDC browser redirect did not complete." }
    $login = Invoke-BaoApi Post "auth/oidc/oidc/poll" @{
        state = $challenge.data.state
        client_nonce = $clientNonce
    } ""
    $userToken = $login.auth.client_token
    if (-not $userToken -or $login.auth.metadata.email -ne "alice@example.test") {
        throw "OIDC login did not return Alice's mapped identity."
    }
    $replayDenied = $false
    try {
        Invoke-BaoApi Post "auth/oidc/oidc/poll" @{
            state = $challenge.data.state
            client_nonce = $clientNonce
        } "" | Out-Null
    } catch {
        $replayDenied = $true
    }
    if (-not $replayDenied) { throw "OIDC replay failure: a consumed state/client nonce pair was accepted." }

    [string]$aliceCsr = New-LabCsr "alice@example.test" "alice"
    Write-Host "OIDC authenticated as alice@example.test; testing allowed issuance."
    $alice = Invoke-BaoApi Post "pki-users/sign/user-mtls" @{
        csr = $aliceCsr
        common_name = "alice@example.test"
        alt_names = "alice@example.test"
        format = "pem"
    } $userToken
    if ($alice.data.certificate -notmatch "BEGIN CERTIFICATE") {
        throw "Alice's certificate was not issued."
    }
    $aliceThumbprint = Install-And-TestLabCertificate $alice.data.certificate

    [string]$serverCsr = New-LabCsr 'localhost' 'server'
    $server = Invoke-BaoApi Post 'pki-users/sign/lab-server' @{
        csr = $serverCsr
        common_name = 'localhost'
        alt_names = 'localhost'
        ip_sans = '127.0.0.1'
        format = 'pem'
    }
    $serverThumbprint = Install-LabServerCertificate $server.data.certificate
    Test-LabMtls $serverThumbprint $aliceThumbprint

    Write-Host "Alice issuance and mTLS authentication succeeded; testing cross-identity denial."
    [string]$bobCsr = New-LabCsr "bob@example.test" "bob"
    $bobDenied = $false
    try {
        Invoke-BaoApi Post "pki-users/sign/user-mtls" @{
            csr = $bobCsr
            common_name = "bob@example.test"
            alt_names = "bob@example.test"
            format = "pem"
        } $userToken | Out-Null
    } catch {
        $bobDenied = $true
    }
    if (-not $bobDenied) { throw "Identity policy failure: Alice was able to request Bob's certificate." }

    $rootPath = Join-Path $labRoot "lab-root.pem"
    [IO.File]::WriteAllText($rootPath, $root.data.certificate, [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{
        OpenBaoVersion = (Invoke-BaoApi Get "sys/health" $null "").version
        OidcIdentity = $login.auth.metadata.email
        AliceIssued = $true
        AliceInstalled = $true
        AliceThumbprint = $aliceThumbprint
        PrivateKeyExportable = $false
        MtlsAuthenticated = $true
        OidcReplayDenied = $replayDenied
        BobDenied = $bobDenied
        RootInstalled = $true
        RootThumbprint = $rootThumbprint
        RootCertificate = $rootPath
        Logs = $logs
    }
} finally {
    if ($mtlsJob) {
        Stop-Job -Job $mtlsJob -ErrorAction SilentlyContinue
        Remove-Job -Job $mtlsJob -Force -ErrorAction SilentlyContinue
    }
    if ($installedThumbprints.Count -gt 0) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            [Security.Cryptography.X509Certificates.StoreName]::My,
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            foreach ($thumbprint in $installedThumbprints) {
                @($store.Certificates | Where-Object Thumbprint -EQ $thumbprint) | ForEach-Object { $store.Remove($_) }
            }
        } catch {
            Write-Warning "Could not remove a temporary lab certificate from CurrentUser\\My: $($_.Exception.Message)"
        } finally {
            $store.Close()
        }
    }
    if ($installedRootThumbprints.Count -gt 0) {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            [Security.Cryptography.X509Certificates.StoreName]::Root,
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            foreach ($thumbprint in $installedRootThumbprints) {
                @($store.Certificates | Where-Object Thumbprint -EQ $thumbprint) | ForEach-Object { $store.Remove($_) }
            }
        } catch {
            Write-Warning "Could not remove the temporary lab root from CurrentUser\\Root: $($_.Exception.Message)"
        } finally {
            $store.Close()
        }
    }
    foreach ($container in $keyContainers) {
        & "$env:SystemRoot\System32\certutil.exe" -user -csp "Microsoft Software Key Storage Provider" -delkey $container 2>$null | Out-Null
    }
    if (-not $KeepProcesses) {
        foreach ($process in @($baoProcess, $mockProcess)) {
            if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        }
    }
}
