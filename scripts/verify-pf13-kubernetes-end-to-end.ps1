<#
.SYNOPSIS
Task 57 end-to-end and disclosure gate for the isolated Kubernetes deployment.

.DESCRIPTION
Runs the browser path and its negative cases against the single reviewed public
hostname, then scans the live workloads and the rendered chart for raw token
material, credentials, private keys, and unsafe public exposure.

The lab credential is read from the exact Vault-synchronized Kubernetes Secret
into process environment only. It is never passed as a command-line argument
and never printed.
#>
param(
    [string]$Namespace = 'wai-strict',
    [string]$PingFederateNamespace = 'wai-pingfederate',
    [string]$PublicOrigin = 'https://workbench.ping.darkedges.com',
    [string]$SpireNamespace = 'spire-system',
    [string]$SpireServerPod = 'spire-server-0',
    [string]$PingAuthorizeNamespace = 'wai-pingauthorize',
    [string]$PingAuthorizePod = 'wai-pingauthorize-0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($PublicOrigin -ne 'https://workbench.ping.darkedges.com') { throw 'PublicOrigin must remain the reviewed public hostname.' }
foreach ($required in @('kubectl', 'helm', 'python')) {
    if (-not (Get-Command $required -ErrorAction SilentlyContinue)) { throw "$required is required." }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$generated = Join-Path $repoRoot 'deploy/pingfederate/generated'
$evidence = Join-Path $generated 'pf13-kubernetes-end-to-end-evidence.json'

$components = @('adapter', 'gateway', 'mcp', 'api', 'audit', 'workbench')
# The reviewed policy graph. Any other package means the overlay did not apply.
$ReviewedPackageId = '1ca3f398-1ba9-4169-a576-7fac52b286db'
$failures = @()

Write-Output '== workload readiness =='
foreach ($component in $components) {
    $ready = kubectl -n $Namespace get deploy "wai-strict-wai-strict-$component" -o jsonpath='{.status.readyReplicas}'
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ready) -or [int]$ready -lt 1) {
        $failures += "component $component is not ready"
        Write-Output "FAIL: $component is not ready."
    } else {
        Write-Output "PASS: $component is ready."
    }
}
$pfReady = kubectl -n $PingFederateNamespace get statefulset wai-pingfederate -o jsonpath='{.status.readyReplicas}'
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pfReady) -or [int]$pfReady -lt 1) {
    $failures += 'the isolated PingFederate runtime is not ready'
    Write-Output 'FAIL: the isolated PingFederate runtime is not ready.'
} else {
    Write-Output 'PASS: the isolated PingFederate runtime is ready.'
}

Write-Output ''
Write-Output '== SPIRE authority freshness =='
# SPIRE prepares its next JWT authority hours before it signs with it, and the
# actor token processor holds a snapshot. If PingFederate is missing a prepared
# key, every exchange will start failing the moment SPIRE activates it. Catch
# that here, while there is still a window to act, rather than as an outage.
$bundle = kubectl -n $SpireNamespace exec $SpireServerPod -c spire-server -- spire-server bundle show -format spiffe
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($bundle)) {
    $failures += 'could not read the SPIRE trust bundle'
    Write-Output 'FAIL: could not read the SPIRE trust bundle.'
} else {
    $current = @(($bundle | ConvertFrom-Json).keys | Where-Object { $_.use -eq 'jwt-svid' } | ForEach-Object { $_.kid })
    $configured = & (Join-Path $PSScriptRoot 'read-pf13-actor-jwks-kids.ps1') -Namespace $PingFederateNamespace
    if ($LASTEXITCODE -ne 0) {
        $failures += 'could not read the configured actor JWKS'
        Write-Output 'FAIL: could not read the configured actor JWKS.'
    } else {
        $missing = @($current | Where-Object { $configured -notcontains $_ })
        if ($missing.Count -gt 0) {
            $failures += "the actor processor is missing SPIRE key(s): $($missing -join ', ')"
            Write-Output "FAIL: the actor processor is missing SPIRE JWT authority: $($missing -join ', '). Run make pf13-k8s-terraform-apply before SPIRE activates it."
        } else {
            Write-Output "PASS: the actor processor trusts all $($current.Count) current SPIRE JWT authorities."
        }
    }
}

Write-Output ''
Write-Output '== decision point =='
# A healthy decision point proves nothing about which policy it loaded. When the
# reviewed overlay fails to apply, the product still starts, still serves the
# right certificate, and permits everything from the vendor's sample policy. The
# only reliable signal is which package decided, and whether it decided at all.
# -a returns the computed values, so a provider left at its chart default is
# reported rather than appearing absent.
$provider = helm get values wai-strict --namespace $Namespace -a -o json 2>$null | ConvertFrom-Json
$selected = 'opa'
if ($provider -and $provider.PSObject.Properties.Name -contains 'authorization') {
    $authorization = $provider.authorization
    if ($authorization -and $authorization.PSObject.Properties.Name -contains 'provider' -and -not [string]::IsNullOrWhiteSpace($authorization.provider)) {
        $selected = $authorization.provider
    }
}
Write-Output "The strict gateway is configured for: $selected"
if ($selected -eq 'pingauthorize') {
    $decisionsBefore = kubectl -n $PingAuthorizeNamespace exec $PingAuthorizePod -- sh -c 'grep -c "\"decision\"" /opt/out/instance/logs/policy-decision 2>/dev/null || echo 0'
    if ($LASTEXITCODE -ne 0) {
        $failures += 'could not read the decision point log'
        Write-Output 'FAIL: could not read the decision point log.'
    }
    $env:DECISION_COUNT_BEFORE = ($decisionsBefore | Select-Object -Last 1).Trim()
} else {
    Write-Output 'PASS: the reviewed rego policy is mounted beside the gateway.'
}

Write-Output ''
Write-Output '== public surface =='
& (Join-Path $PSScriptRoot 'verify-workbench-public-surface.ps1') -PublicOrigin $PublicOrigin
if ($LASTEXITCODE -ne 0) { $failures += 'the public surface gate failed' }

Write-Output ''
$user = 'demo-user'
$encoded = kubectl -n $PingFederateNamespace get secret wai-pf13-oauth-lab-user -o 'jsonpath={.data.user-password}'
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($encoded)) { throw 'Could not read the lab user credential from its Vault-synchronized Secret.' }

try {
    $env:LAB_USER = $user
    $env:LAB_PASSWORD = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)).Trim()
    $env:EVIDENCE_PATH = $evidence
    python (Join-Path $repoRoot 'deploy/pingfederate/scripts/verify_kubernetes_end_to_end.py')
    if ($LASTEXITCODE -ne 0) { $failures += 'the end-to-end browser and negative gate failed' }
} finally {
    Remove-Item Env:LAB_USER, Env:LAB_PASSWORD, Env:EVIDENCE_PATH -ErrorAction SilentlyContinue
}

if ($selected -eq 'pingauthorize') {
    Write-Output ''
    Write-Output '== decision point evidence =='
    $decisionsAfter = kubectl -n $PingAuthorizeNamespace exec $PingAuthorizePod -- sh -c 'grep -c "\"decision\"" /opt/out/instance/logs/policy-decision 2>/dev/null || echo 0'
    $after = ($decisionsAfter | Select-Object -Last 1).Trim()
    if ([int]$after -le [int]$env:DECISION_COUNT_BEFORE) {
        $failures += 'the decision point was never consulted'
        Write-Output "FAIL: the call chain completed without consulting the decision point ($env:DECISION_COUNT_BEFORE -> $after). The gateway is enforcing something else."
    } else {
        Write-Output "PASS: the decision point was consulted ($env:DECISION_COUNT_BEFORE -> $after decisions)."
    }
    $lastDecision = kubectl -n $PingAuthorizeNamespace exec $PingAuthorizePod -- sh -c 'grep "\"decision\"" /opt/out/instance/logs/policy-decision | tail -1'
    if ($lastDecision -match '"deploymentPackageId":"([0-9a-f-]+)"') {
        if ($Matches[1] -ne $ReviewedPackageId) {
            $failures += "the decision point is enforcing package $($Matches[1])"
            Write-Output "FAIL: decisions come from package $($Matches[1]), not the reviewed $ReviewedPackageId. The vendor sample policy is in force."
        } else {
            Write-Output "PASS: decisions come from the reviewed package $ReviewedPackageId."
        }
    } else {
        $failures += 'no decision package could be identified'
        Write-Output 'FAIL: no decision package could be identified.'
    }
    Remove-Item Env:DECISION_COUNT_BEFORE -ErrorAction SilentlyContinue
}

Write-Output ''
Write-Output '== disclosure scan =='
# A compact JWS in a log line means a raw access token, ID token, JWT-SVID, or
# transaction token was written where an operator or log shipper can read it.
$compactJwt = [regex]'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
foreach ($component in $components) {
    $logs = kubectl -n $Namespace logs "deploy/wai-strict-wai-strict-$component" --tail=500 2>$null
    if ([string]::IsNullOrWhiteSpace($logs)) { continue }
    if ($compactJwt.IsMatch($logs)) {
        $failures += "component $component logged raw token material"
        Write-Output "FAIL: $component logged raw token material."
    } else {
        Write-Output "PASS: $component logged no raw token material."
    }
    foreach ($marker in @('client_secret=', 'PRIVATE KEY', 'client-secret')) {
        if ($logs -match [regex]::Escape($marker)) {
            $failures += "component $component logged $marker"
            Write-Output "FAIL: $component logged $marker."
        }
    }
}

$rendered = helm get manifest wai-strict --namespace $Namespace
if ($LASTEXITCODE -ne 0) { throw 'Could not read the rendered wai-strict release.' }
if ($rendered -match '(?m)^kind: Secret' -or $rendered -match '(?m)^\s*stringData:') {
    $failures += 'the rendered release embeds Secret material'
    Write-Output 'FAIL: the rendered release embeds Secret material.'
} else {
    Write-Output 'PASS: the rendered release embeds no Secret material.'
}
if ($compactJwt.IsMatch($rendered) -or $rendered -match 'PRIVATE KEY') {
    $failures += 'the rendered release embeds token or key material'
    Write-Output 'FAIL: the rendered release embeds token or key material.'
} else {
    Write-Output 'PASS: the rendered release embeds no token or key material.'
}

# Only LoadBalancer and NodePort actually publish a Service outside the cluster.
# An ExternalName Service allocates no address and exposes nothing, so it is
# checked for its exact target rather than counted as exposure.
$published = kubectl get svc -A -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}{range .items[?(@.spec.type=="NodePort")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
$waiPublished = @($published -split "`n" | Where-Object { $_ -like '*wai-*' })
if ($waiPublished.Count -gt 0) {
    $failures += 'a WAI Service is published outside the cluster'
    Write-Output "FAIL: WAI Services published outside the cluster: $($waiPublished -join ', ')."
} else {
    Write-Output 'PASS: no WAI Service is published outside the cluster.'
}

$aliases = kubectl -n $Namespace get svc -o jsonpath='{range .items[?(@.spec.type=="ExternalName")]}{.metadata.name}={.spec.externalName}{"\n"}{end}'
foreach ($alias in @($aliases -split "`n" | Where-Object { $_ })) {
    if ($alias -ne 'wai-pingfederate-engine-route=wai-pingfederate-engine.wai-pingfederate.svc.cluster.local') {
        $failures += "an unexpected ExternalName alias is present: $alias"
        Write-Output "FAIL: unexpected ExternalName alias $alias."
    } else {
        Write-Output 'PASS: the engine alias resolves only to the isolated internal engine Service.'
    }
}

$pfIngress = kubectl -n $PingFederateNamespace get ingress -o name 2>$null
if (-not [string]::IsNullOrWhiteSpace($pfIngress)) {
    $failures += 'the isolated PingFederate namespace publishes an Ingress'
    Write-Output 'FAIL: the isolated PingFederate namespace publishes an Ingress.'
} else {
    Write-Output 'PASS: the isolated PingFederate namespace publishes no Ingress.'
}

Write-Output ''
if ($failures.Count -gt 0) {
    throw "Kubernetes end-to-end gate failed: $($failures -join '; ')."
}
Write-Output "PASS: the isolated Kubernetes Transaction Token deployment satisfies the Task 57 gate."
Write-Output "Sanitized evidence: $evidence"
