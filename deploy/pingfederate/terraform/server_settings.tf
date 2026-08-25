# PingFederate renders every hosted browser page against its configured runtime
# base URL. When the base URL is an internal engine address, the hosted HTML
# form login page emits a `<base href>` and root-relative form action that a
# browser resolves back to that unreachable internal origin, so the user can
# render the login page but never submit it.
#
# The base URL is therefore the external HTTPS origin the browser actually
# reaches. It is also the issuer of the tokens this logical TTS signs, which
# keeps the isolated Kubernetes deployment's issuer distinct from the Docker
# harness rather than colliding with it. Consumers allowlist this exact issuer;
# see `global.pingFederate.issuer` in the reviewed Helm values and the
# transaction access token manager's Issuer field.
#
# nginx and Cloudflare remain routing/TLS boundaries only. Setting the base URL
# does not make any forwarded header an identity assertion.
resource "pingfederate_server_settings" "runtime" {
  federation_info = {
    base_url = var.pf_base_url

    # SAML is not part of the reviewed WAI profile and this deployment defines no
    # SAML connection, so the entity ID is inert. The provider still requires a
    # non-empty value, so it is pinned to the same isolated origin rather than to
    # an unrelated or shared federation identity.
    saml_2_entity_id = var.pf_base_url
  }
}
