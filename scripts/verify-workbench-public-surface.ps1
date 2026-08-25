param(
    [string]$PublicOrigin = 'https://workbench.ping.darkedges.com',
    [string]$IngressOrigin = '',
    [string]$ExpectedHost = 'workbench.ping.darkedges.com',
    [string]$WrongHost = 'not-workbench.ping.darkedges.com'
)

$ErrorActionPreference = 'Stop'
if ($PublicOrigin -notmatch '^https://[^/?#]+(?::[0-9]+)?$') { throw 'PublicOrigin must be one fixed HTTPS origin.' }
if ([string]::IsNullOrWhiteSpace($IngressOrigin)) { $IngressOrigin = $PublicOrigin }
if ($IngressOrigin -ne $PublicOrigin -and $IngressOrigin -notmatch '^http://localhost(?::[0-9]+)?$') { throw 'IngressOrigin may only override the public origin with a localhost HTTP ingress endpoint.' }
if ($ExpectedHost -ne 'workbench.ping.darkedges.com') { throw 'ExpectedHost must remain the reviewed public hostname.' }
if ($WrongHost -eq $ExpectedHost -or $WrongHost -notmatch '^[A-Za-z0-9.-]+$') { throw 'WrongHost must be a distinct valid hostname.' }

$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)

function Send-Probe([string]$Path, [string]$HostHeader) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$IngressOrigin$Path")
    $request.Headers.Host = $HostHeader
    try { return $client.SendAsync($request).GetAwaiter().GetResult() } finally { $request.Dispose() }
}

try {
    $jwks = Send-Probe '/pf/JWKS' $ExpectedHost
    try {
        if ([int]$jwks.StatusCode -ne 200 -or $jwks.Content.Headers.ContentType.MediaType -notmatch 'json') { throw 'The allowlisted JWKS engine path did not return JSON successfully.' }
    } finally { $jwks.Dispose() }

    foreach ($path in @('/pf-admin-api/v1/version', '/pf-admin/', '/pingfederate/app', '/internal/adapter', '/internal/audit')) {
        $response = Send-Probe $path $ExpectedHost
        try {
            if ([int]$response.StatusCode -lt 400) { throw "Forbidden public path $path returned HTTP $([int]$response.StatusCode)." }
        } finally { $response.Dispose() }
    }

    $wrongHostResponse = Send-Probe '/pf/JWKS' $WrongHost
    try {
        if ([int]$wrongHostResponse.StatusCode -lt 400) { throw 'An unapproved Host header reached the public route.' }
    } finally { $wrongHostResponse.Dispose() }
} finally {
    $client.Dispose()
    $handler.Dispose()
}

Write-Output 'PASS: only the reviewed hostname and PingFederate engine paths are publicly reachable.'
