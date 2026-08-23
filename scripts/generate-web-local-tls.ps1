param(
    [string]$OutputDirectory = 'deploy/web/generated',
    [switch]$Trust
)

$ErrorActionPreference = 'Stop'
$resolvedOutput = Join-Path (Get-Location) $OutputDirectory
[IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null

$previousCertificatePath = Join-Path $resolvedOutput 'local-web-cert.pem'
if ($Trust -and [IO.File]::Exists($previousCertificatePath)) {
    $previousPEM = [IO.File]::ReadAllText($previousCertificatePath)
    $previousCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($previousPEM)
    $rootStore = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::Root,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $rootStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches = $rootStore.Certificates.Find(
            [Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $previousCertificate.Thumbprint, $false)
        foreach ($match in $matches) { $rootStore.Remove($match) }
    } finally {
        $rootStore.Dispose()
        $previousCertificate.Dispose()
    }
}

$notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
$notAfter = [DateTimeOffset]::UtcNow.AddDays(30)
$leafKey = [Security.Cryptography.RSA]::Create(2048)
$leaf = $null
try {
    $leafRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost', $leafKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $leafRequest.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $leafRequest.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, $true))
    $eku = [Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $leafRequest.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $true))
    $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $san.AddIpAddress([Net.IPAddress]::Loopback)
    $leafRequest.CertificateExtensions.Add($san.Build($true))
    $leafRequest.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($leafRequest.PublicKey, $false))
    $leaf = $leafRequest.CreateSelfSigned($notBefore, $notAfter)

    $utf8 = [Text.UTF8Encoding]::new($false)
    $leafPEM = $leaf.ExportCertificatePem()
    [IO.File]::WriteAllText((Join-Path $resolvedOutput 'local-web-cert.pem'), $leafPEM, $utf8)
    [IO.File]::WriteAllText((Join-Path $resolvedOutput 'server-cert.pem'), $leafPEM, $utf8)
    [IO.File]::WriteAllText((Join-Path $resolvedOutput 'server-key.pem'), $leafKey.ExportPkcs8PrivateKeyPem(), $utf8)
    [IO.File]::Delete((Join-Path $resolvedOutput 'local-web-ca.pem'))

    if ($Trust) {
        & certutil.exe -f -user -addstore Root (Join-Path $resolvedOutput 'local-web-cert.pem')
        if ($LASTEXITCODE -ne 0) { throw 'Could not trust the local web development certificate.' }
        Write-Output 'Trusted only the public localhost certificate for the current user.'
    }
    Write-Output "Generated short-lived localhost TLS material in $OutputDirectory."
} finally {
    if ($leaf) { $leaf.Dispose() }
    $leafKey.Dispose()
}
