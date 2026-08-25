#!/usr/bin/env python3
"""Task 57 end-to-end gate for the isolated Kubernetes Transaction Token solution.

The gate drives the real browser path through the single reviewed public
hostname: PingFederate's hosted login form, scope consent, the exact callback,
the strict RFC 8693 exchange, and the strict call chain through the protected
API. It then proves the negative cases that are observable from a browser and
scans the collected evidence for disclosure.

Everything here runs from the position of an ordinary external user. Negative
cases that require a workload inside the SPIFFE mesh -- a forged logical
AgentID, a wrong SPIFFE workload, a stolen token replayed over another mTLS
identity, and legacy Bearer transport -- are proven by the Go suite, which can
construct those callers directly. See docs/implementation-notes-task-57.md.

No credential, access token, ID token, authorization code, or transaction token
is ever printed. Evidence is recorded by SHA-256 fingerprint only.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# The application and the authorization server have separate origins, so the
# browser treats them as distinct sites and neither one's session cookie reaches
# the other.
HOST = "workbench.ping.darkedges.com"
PUBLIC = f"https://{HOST}"
PF_HOST = "tst.ping.darkedges.com"
PF_PUBLIC = f"https://{PF_HOST}"
CLIENT_ID = "wai-web-app"
REDIRECT_URI = f"{PUBLIC}/oauth/callback"
APPROVED_SCOPES = ["mcp:invoke", "openid"]
APPROVED_TOOL = "system.whoami"
APPROVED_PURPOSE = "system.whoami"
STRICT_SCOPE = "mcp.system.whoami"
TRUST_DOMAIN = "example.org"
MAXIMUM_TOKEN_LIFETIME_SECONDS = 60

# A compact JWS with three base64url segments. Any match inside evidence or a
# log line means raw token material escaped.
COMPACT_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

failures: list[str] = []
checks = 0


def record(name: str, ok: bool, detail: str = "") -> bool:
    global checks
    checks += 1
    print(f"{'PASS' if ok else 'FAIL'}: {name}{(' -- ' + detail) if detail else ''}")
    if not ok:
        failures.append(name)
    return ok


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def absolute(url: str, base: str = PUBLIC) -> str:
    if url.startswith("/"):
        return base + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in (HOST, PF_HOST):
        raise SystemExit(f"Refusing to follow a redirect off the reviewed hostnames: {parts.netloc}")
    return url


def call(url: str, data: bytes | None = None, extra: dict | None = None, form: bool = True):
    headers = {"User-Agent": "wai-task-57-gate/1.0"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        parts = urllib.parse.urlsplit(url)
        origin = urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        headers["Origin"] = origin
        headers["Referer"] = origin + "/"
    headers.update(extra or {})
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(request, timeout=30) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()
    except urllib.error.URLError as error:
        raise SystemExit(f"Unable to reach the reviewed public hostname: {error.reason}")


user = os.getenv("LAB_USER")
password = os.getenv("LAB_PASSWORD")
if not user or not password:
    raise SystemExit("Set LAB_USER and LAB_PASSWORD from the Vault-synchronized Kubernetes Secret.")

print("== positive path ==")

status, headers, _ = call(absolute("/login"))
record("workbench starts an authorization code flow", status in (302, 303), f"HTTP {status}")
authorize = headers.get("Location", "")
record(
    "the authorization request leaves the application origin",
    urllib.parse.urlsplit(authorize).netloc == PF_HOST,
    urllib.parse.urlsplit(authorize).netloc,
)
query = urllib.parse.parse_qs(urllib.parse.urlsplit(authorize).query)
record(
    "authorization request pins PKCE, state, nonce, and the exact callback",
    query.get("code_challenge_method") == ["S256"]
    and bool(query.get("code_challenge"))
    and bool(query.get("state"))
    and bool(query.get("nonce"))
    and query.get("redirect_uri") == [REDIRECT_URI]
    and query.get("client_id") == [CLIENT_ID],
)

status, _, body = call(absolute(authorize))
page = body.decode("utf-8", "replace")
record("PingFederate serves the hosted login form", status == 200, f"HTTP {status}")
base = re.search(r'<base href="([^"]+)"', page)
record(
    "hosted login renders against the authorization server origin",
    bool(base) and base.group(1).rstrip("/") == PF_PUBLIC,
    base.group(1) if base else "no base href",
)
form = re.search(r'<form method="POST" action="([^"]+)"', page)
if not form:
    raise SystemExit("FAIL: the hosted login form is absent.")

# A login page that renders is not the same as a login page that works. Its
# stylesheet and scripts are loaded relative to the base href, so a path
# allowlist that covers only the protocol prefixes yields a page that appears
# fine to a status-code check and is unstyled and non-functional in a browser.
subresources = sorted({
    urllib.parse.urljoin(base.group(1), reference)
    for reference in re.findall(r"""(?:href|src)=["']([^"']+\.(?:css|js))["']""", page)
    # /cdn-cgi/ is injected by Cloudflare, not served by PingFederate. It is
    # excluded from the assertions because this gate tests the deployment, but
    # its presence is reported: an edge that rewrites scripts on the credential
    # entry page is worth an operator knowing about.
    if not reference.startswith(("http://", "https://", "//", "/cdn-cgi/"))
})
injected = sorted({
    reference for reference in re.findall(r"""(?:href|src)=["']([^"']+\.js)["']""", page)
    if reference.startswith("/cdn-cgi/")
})
if injected:
    print(f"NOTE: the edge injects {len(injected)} script(s) into the hosted login page: {', '.join(injected)}")
record("the hosted login page declares its stylesheet and scripts", len(subresources) > 0, f"{len(subresources)} references")
for reference in subresources:
    parts = urllib.parse.urlsplit(reference)
    if parts.netloc != PF_HOST:
        record(f"sub-resource {parts.path} stays on the authorization server origin", False, parts.netloc)
        continue
    status, sub_headers, _ = call(reference)
    kind = (sub_headers.get("Content-Type") or "").split(";")[0]
    expected = "text/css" if parts.path.endswith(".css") else "javascript"
    record(
        f"the hosted login page can load {parts.path}",
        status == 200 and expected in kind,
        f"HTTP {status} {kind}",
    )

credentials = urllib.parse.urlencode({"pf.username": user, "pf.pass": password, "pf.ok": "clicked"}).encode()
status, headers, body = call(absolute(form.group(1), PF_PUBLIC), data=credentials)
location = headers.get("Location")
if status == 200:
    consent = body.decode("utf-8", "replace")
    action = re.search(r'<form method="post" action="([^"]+)"', consent)
    csrf = re.search(r'name="cSRFToken" value="([^"]*)"', consent)
    offered = sorted(re.findall(r'<input type="checkbox" name="scope" value="([^"]+)"', consent))
    record("consent requests exactly the approved scopes", offered == APPROVED_SCOPES, str(offered))
    if not action or not csrf:
        raise SystemExit("FAIL: credentials did not reach the consent step.")
    fields = [("check-user-approved-scope", "true"), ("cSRFToken", csrf.group(1)), ("pf.oauth.authz.consent", "allow")]
    fields += [("scope", scope) for scope in offered]
    status, headers, _ = call(absolute(action.group(1), PF_PUBLIC), data=urllib.parse.urlencode(fields).encode())
    location = headers.get("Location")
record("user authenticates and approves the request", status in (302, 303), f"HTTP {status}")

for _ in range(6):
    if location and "/oauth/callback" in location:
        break
    status, headers, _ = call(absolute(location, PF_PUBLIC))
    if status not in (302, 303):
        raise SystemExit(f"FAIL: unexpected HTTP {status} before the callback.")
    location = headers["Location"]
else:
    raise SystemExit("FAIL: PingFederate never redirected to the reviewed callback.")
record("PingFederate returns to the exact reviewed callback", location.startswith(REDIRECT_URI))

status, _, _ = call(absolute(location))
record("workbench completes the code exchange", status in (302, 303, 200), f"HTTP {status}")

status, _, body = call(absolute("/api/session"))
record("workbench establishes an authenticated session", status == 200, f"HTTP {status}")
session = json.loads(body)
record("session subject is the authenticated user", session.get("subject") == user, str(session.get("subject")))
csrf_token = session["csrf_token"]

approved = json.dumps({"tool": APPROVED_TOOL, "purpose": APPROVED_PURPOSE}).encode()
status, _, body = call(
    absolute("/api/interactions"), data=approved, form=False, extra={"X-CSRF-Token": csrf_token}
)
record("strict call chain completes through the protected API", status in (200, 201), f"HTTP {status}")
interaction = json.loads(body)
transaction_id = interaction.get("transaction_id", "")
record("the completed interaction reports one transaction identifier", bool(transaction_id) and interaction.get("status") == "completed")

print("\n== negative path ==")

status, _, _ = call(
    absolute("/api/interactions"),
    data=json.dumps({"tool": "customer.read", "purpose": APPROVED_PURPOSE}).encode(),
    form=False,
    extra={"X-CSRF-Token": csrf_token},
)
record("unapproved tool is rejected", status == 400, f"HTTP {status}")

status, _, _ = call(
    absolute("/api/interactions"),
    data=json.dumps({"tool": APPROVED_TOOL, "purpose": "customer.read"}).encode(),
    form=False,
    extra={"X-CSRF-Token": csrf_token},
)
record("unapproved purpose is rejected", status == 400, f"HTTP {status}")

status, _, _ = call(absolute("/api/interactions"), data=approved, form=False, extra={"X-CSRF-Token": "not-the-token"})
record("a wrong CSRF token is rejected", status == 401, f"HTTP {status}")

status, _, _ = call(
    absolute("/api/interactions"), data=approved, form=False, extra={"X-CSRF-Token": csrf_token, "Origin": "https://attacker.invalid"}
)
record("a cross-origin submission is rejected", status == 401, f"HTTP {status}")

anonymous = urllib.request.build_opener(NoRedirect)
try:
    request = urllib.request.Request(
        absolute("/api/interactions"), data=approved,
        headers={
            "Content-Type": "application/json", "Origin": PUBLIC, "X-CSRF-Token": csrf_token,
            # Without an explicit agent the edge answers 403 before the workbench
            # ever sees the request, which would hide the application's own answer.
            "User-Agent": "wai-task-57-gate/1.0",
        },
    )
    with anonymous.open(request, timeout=30) as response:
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
record("an unauthenticated session is rejected", status == 401, f"HTTP {status}")

for name, override in (
    ("a forged redirect URI is rejected", {"redirect_uri": "https://attacker.invalid/oauth/callback"}),
    ("an unapproved scope is rejected", {"scope": "openid admin"}),
):
    forged = {k: v[0] for k, v in query.items()}
    forged.update(override)
    status, forged_headers, forged_body = call(absolute("/as/authorization.oauth2?" + urllib.parse.urlencode(forged), PF_PUBLIC))
    # An unusable redirect URI must fail on PingFederate's own error page, because
    # returning an error to an unverified callback would itself be the leak. A
    # rejected scope is instead an OAuth error delivered to the exact registered
    # callback, so the proof is the error code, not the status.
    redirected = urllib.parse.parse_qs(urllib.parse.urlsplit(forged_headers.get("Location", "")).query)
    rejected = status >= 400 or "error" in redirected
    detail = f"HTTP {status}" + (f" {redirected['error'][0]}" if "error" in redirected else "")
    if "error" in redirected:
        rejected = rejected and forged_headers["Location"].startswith(REDIRECT_URI)
    record(name, rejected, detail)

for base, label in ((PUBLIC, "application"), (PF_PUBLIC, "authorization server")):
    for path in ("/pf-admin-api/v1/version", "/pf-admin/", "/internal/adapter", "/internal/audit"):
        status, _, _ = call(absolute(path, base))
        record(f"{label} origin keeps {path} unreachable", status >= 400, f"HTTP {status}")

# The origin split only delivers cookie isolation if the engine really has left
# the application hostname. While both served it, the browser still treated the
# authorization server and the application as one origin.
for path in ("/pf/JWKS", "/idp/startSSO.ping"):
    status, _, _ = call(absolute(path, PUBLIC))
    record(f"engine path {path} no longer answers on the application origin", status >= 400, f"HTTP {status}")

print("\n== evidence ==")

status, _, body = call(absolute("/api/interactions"))
record("workbench exposes the recorded audit trail", status == 200, f"HTTP {status}")
records = json.loads(body)
chain = [r for r in records if r.get("transaction_id") == transaction_id]
record("every hop correlates to one transaction identifier", len(chain) >= 3, f"{len(chain)} events")

fingerprints = {r["verified_transaction_token"]["fingerprint"] for r in chain if r.get("verified_transaction_token")}
record("the transaction token is immutable across the chain", len(fingerprints) == 1, f"{len(fingerprints)} distinct fingerprints")

decisions = {r.get("decision") for r in chain}
record("every correlated hop allowed the request", decisions == {"allow"}, str(sorted(decisions)))

callers = {r.get("immediate_caller_spiffe_id") for r in chain if r.get("immediate_caller_spiffe_id")}
record("immediate caller identity varies per hop", len(callers) > 1, f"{len(callers)} distinct SPIFFE callers")

for evidence in (r.get("verified_transaction_token") for r in chain):
    if not evidence:
        continue
    lifetime = evidence.get("expires_at"), evidence.get("issued_at")
    record(
        "transaction evidence pins the strict audience, scope, and issuer",
        evidence.get("audience") == [TRUST_DOMAIN]
        and evidence.get("scope") == [STRICT_SCOPE]
        and evidence.get("issuer") == PF_PUBLIC
        and evidence.get("kind") == "txn_token",
    )
    break

serialized = json.dumps(records)
record("audit evidence carries no raw token material", not COMPACT_JWT.search(serialized))
record("audit evidence carries no credential field", not any(k in serialized for k in ("client_secret", "password", "private_key", "refresh_token")))

evidence_path = os.getenv("EVIDENCE_PATH")
if evidence_path:
    summary = {
        "applicationOrigin": PUBLIC,
        "authorizationServerOrigin": PF_PUBLIC,
        "transactionId": transaction_id,
        "hops": [
            {k: r.get(k) for k in ("event_type", "decision", "reason_code", "immediate_caller_spiffe_id", "submitting_spiffe_id")}
            for r in chain
        ],
        "tokenFingerprints": sorted(fingerprints),
        "checks": checks,
        "failures": failures,
    }
    with open(evidence_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print(f"\nSanitized evidence written to: {evidence_path}")

print()
if failures:
    print(f"FAIL: {len(failures)} of {checks} checks failed: {', '.join(failures)}")
    sys.exit(1)
print(f"PASS: all {checks} Kubernetes end-to-end checks succeeded.")
