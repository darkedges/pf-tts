param(
    [string]$PublicOrigin = 'https://workbench.ping.darkedges.com',
    [string]$PingFederateOrigin = 'https://tst.ping.darkedges.com',
    [string]$IngressOrigin = '',
    [string]$ExpectedHost = 'workbench.ping.darkedges.com',
    [string]$PingFederateHost = 'tst.ping.darkedges.com',
    [string]$WrongHost = 'not-workbench.ping.darkedges.com'
)

$ErrorActionPreference = 'Stop'
if ($PublicOrigin -notmatch '^https://[^/?#]+(?::[0-9]+)?$') { throw 'PublicOrigin must be one fixed HTTPS origin.' }
if ($PingFederateOrigin -notmatch '^https://[^/?#]+(?::[0-9]+)?$') { throw 'PingFederateOrigin must be one fixed HTTPS origin.' }
if ([string]::IsNullOrWhiteSpace($IngressOrigin)) { $IngressOrigin = $PublicOrigin }
if ($IngressOrigin -ne $PublicOrigin -and $IngressOrigin -notmatch '^http://localhost(?::[0-9]+)?$') { throw 'IngressOrigin may only override the public origin with a localhost HTTP ingress endpoint.' }
if ($ExpectedHost -ne 'workbench.ping.darkedges.com') { throw 'ExpectedHost must remain the reviewed application hostname.' }
if ($PingFederateHost -ne 'tst.ping.darkedges.com') { throw 'PingFederateHost must remain the reviewed authorization server hostname.' }
if ($PingFederateHost -eq $ExpectedHost) { throw 'The authorization server must not share the application origin.' }
if ($WrongHost -eq $ExpectedHost -or $WrongHost -eq $PingFederateHost -or $WrongHost -notmatch '^[A-Za-z0-9.-]+$') { throw 'WrongHost must be a distinct valid hostname.' }

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
    # The engine paths belong to the authorization server's own origin.
    $jwks = Send-Probe '/pf/JWKS' $PingFederateHost
    try {
        if ([int]$jwks.StatusCode -ne 200 -or $jwks.Content.Headers.ContentType.MediaType -notmatch 'json') { throw 'The allowlisted JWKS engine path did not return JSON successfully.' }
    } finally { $jwks.Dispose() }

    # The origin split is only real if the engine is no longer reachable on the
    # application hostname. While both worked, the browser still treated the
    # authorization server and the application as one origin.
    foreach ($path in @('/pf/JWKS', '/as/authorization.oauth2', '/idp/startSSO.ping')) {
        $leaked = Send-Probe $path $ExpectedHost
        try {
            if ([int]$leaked.StatusCode -lt 400) { throw "Engine path $path is still served on the application origin (HTTP $([int]$leaked.StatusCode))." }
        } finally { $leaked.Dispose() }
    }

    foreach ($hostHeader in @($ExpectedHost, $PingFederateHost)) {
        foreach ($path in @('/pf-admin-api/v1/version', '/pf-admin/', '/pingfederate/app', '/internal/adapter', '/internal/audit')) {
            $response = Send-Probe $path $hostHeader
            try {
                if ([int]$response.StatusCode -lt 400) { throw "Forbidden public path $path returned HTTP $([int]$response.StatusCode) on $hostHeader." }
            } finally { $response.Dispose() }
        }
    }

    $wrongHostResponse = Send-Probe '/pf/JWKS' $WrongHost
    try {
        if ([int]$wrongHostResponse.StatusCode -lt 400) { throw 'An unapproved Host header reached the public route.' }
    } finally { $wrongHostResponse.Dispose() }
} finally {
    $client.Dispose()
    $handler.Dispose()
}

Write-Output 'PASS: the application and authorization server origins are separate, and only the reviewed engine paths are publicly reachable.'
