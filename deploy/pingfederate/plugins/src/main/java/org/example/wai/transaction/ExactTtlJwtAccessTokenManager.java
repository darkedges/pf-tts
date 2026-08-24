package org.example.wai.transaction;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetails;
import com.pingidentity.sdk.internal.interfaces.PkCertWrapper;
import com.pingidentity.sdk.internal.services.ServiceFactory;
import com.pingidentity.sdk.internal.services.interfaces.KeyAccessorService;
import com.pingidentity.sdk.oauth20.AccessToken;
import com.pingidentity.sdk.oauth20.BearerAccessTokenManagementPlugin;
import com.pingidentity.sdk.oauth20.IssuedAccessToken;
import com.pingidentity.sdk.oauth20.Scope;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.DsigKeypairFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

public final class ExactTtlJwtAccessTokenManager implements BearerAccessTokenManagementPlugin {
  static final String CERTIFICATE = "Signing Certificate";
  static final String KEY_ID = "Key ID";
  static final String ISSUER = "Issuer";
  static final String AUDIENCE = "Audience";
  static final String LIFETIME = "Token Lifetime Seconds";
  static final String AGENT_BINDINGS = "Agent Bindings";
  static final String PURPOSE = "Transaction Purpose";
	static final String TOKEN_PROFILE = "Token Profile";
	static final String TRANSACTION_TARGET = "Transaction Target";
	static final String TRANSACTION_TOOL = "Transaction Tool";
	static final String TRANSACTION_SCOPE = "Transaction Scope";
  private static final Set<String> CONTRACT = Set.of("sub", "agent_id", "agent_instance_id",
      "workload_id", "transaction_id", "transaction_purpose", "scope", "aud");
  private volatile TransactionJwtIssuer issuer;
  private volatile JwtConsumer validator;
  private volatile TrustedTransactionMetadata metadata;
	private volatile TokenProfile profile;

  @Override public void configure(Configuration configuration) {
    String alias = required(configuration.getFieldValue(CERTIFICATE), CERTIFICATE);
    PkCertWrapper cert = ServiceFactory.getSingleImpl(KeyAccessorService.class).getDsigPkCert(alias);
    if (cert == null || cert.getPrivateKey() == null || cert.getX509Certificate() == null) {
      throw new IllegalArgumentException("configured PingFederate signing certificate is unavailable");
    }
    String issuerName = required(configuration.getFieldValue(ISSUER), ISSUER);
    String audience = required(configuration.getFieldValue(AUDIENCE), AUDIENCE);
    int lifetime = configuration.getIntFieldValue(LIFETIME);
	TokenProfile selectedProfile = TokenProfile.parse(required(configuration.getFieldValue(TOKEN_PROFILE), TOKEN_PROFILE));
	if (selectedProfile == TokenProfile.TRANSACTION_TOKEN_V11 && !isTrustDomain(audience)) {
	  throw new IllegalArgumentException("strict transaction-token Audience must be an exact Trust Domain");
	}
	issuer = new TransactionJwtIssuer(cert.getPrivateKey(), configuration.getFieldValue(KEY_ID),
			issuerName, audience, lifetime, Clock.systemUTC(), selectedProfile,
			configuration.getFieldValue(TRANSACTION_TARGET), configuration.getFieldValue(TRANSACTION_TOOL),
			configuration.getFieldValue(TRANSACTION_SCOPE));
	profile = selectedProfile;
    metadata = new TrustedTransactionMetadata(TrustedTransactionMetadata.parseBindings(
        configuration.getFieldValue(AGENT_BINDINGS)),
        configuration.getFieldValue(PURPOSE),
        () -> UUID.randomUUID().toString());
    validator = new JwtConsumerBuilder().setRequireExpirationTime().setRequireIssuedAt().setRequireSubject()
		.setExpectedIssuer(issuerName).setExpectedAudience(audience)
		.setExpectedType(true, selectedProfile == TokenProfile.TRANSACTION_TOKEN_V11 ? "txntoken+jwt" : "at+jwt")
		.setVerificationKey(cert.getX509Certificate().getPublicKey())
        .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
            AlgorithmIdentifiers.RSA_USING_SHA256)).build();
  }

  @Override public IssuedAccessToken issueAccessToken(Map<String, AttributeValue> attributes, Scope scope,
      String clientId, String accessGrantGuid, int ignoredLifetime, AuthorizationDetails authorizationDetails) {
    TransactionJwtIssuer current = issuer;
    TrustedTransactionMetadata currentMetadata = metadata;
    if (current == null || currentMetadata == null) throw new IllegalStateException("exact-TTL ATM is not configured");
    Map<String,String> values = new HashMap<>();
    for (String name : CONTRACT) {
      AttributeValue value = attributes.get(name);
      if (value != null) values.put(name, value.getValue());
    }
    IssuedTransactionToken token = current.issue(currentMetadata.derive(values), scope == null ? null : scope.getScopeStr());
    return new IssuedAccessToken(token.value(), "Bearer", token.expiresAtMillis());
  }

  @Override public AccessToken validateAccessToken(String compactJwt) {
    JwtConsumer current = validator;
    if (current == null || compactJwt == null || compactJwt.isBlank()) return null;
    try {
      JwtClaims claims = current.processToClaims(compactJwt);
      Map<String,AttributeValue> attributes = new HashMap<>();
      for (String name : CONTRACT) {
        if (claims.hasClaim(name)) attributes.put(name, new AttributeValue(String.valueOf(claims.getClaimValue(name))));
      }
      return new AccessToken(claims.getExpirationTime().getValueInMillis(), attributes,
          attributes.getOrDefault("scope", new AttributeValue("")).getValue(), "", "");
    } catch (Exception e) {
      return null;
    }
  }

  @Override public PluginDescriptor getPluginDescriptor() {
    GuiConfigDescriptor gui = new GuiConfigDescriptor("Issues RS256 transaction JWTs with an exact seconds-level TTL.");
    DsigKeypairFieldDescriptor certificate = new DsigKeypairFieldDescriptor(CERTIFICATE, "PingFederate-managed signing certificate.");
    certificate.addValidator(new RequiredFieldValidator()); gui.addField(certificate);
    gui.addField(requiredField(KEY_ID, "Stable non-secret JWT key ID."));
    gui.addField(requiredField(ISSUER, "Required transaction JWT issuer."));
    gui.addField(requiredField(AUDIENCE, "Required transaction JWT audience."));
    gui.addField(requiredField(LIFETIME, "Exact lifetime in seconds; allowed range 1 through 60."));
    gui.addField(requiredField(AGENT_BINDINGS, "Newline-separated exact SPIFFEID=AgentID trusted bindings."));
    gui.addField(requiredField(PURPOSE, "Allowlisted purpose minted into transaction tokens."));
	gui.addField(requiredField(TOKEN_PROFILE, "Explicit legacy-wai-jwt or ietf-txn-token-v11 profile; no auto-detection."));
	gui.addField(requiredField(TRANSACTION_TARGET, "Fixed trusted target used only by the strict transaction-token profile."));
	gui.addField(requiredField(TRANSACTION_TOOL, "Fixed trusted tool used only by the strict transaction-token profile."));
	gui.addField(requiredField(TRANSACTION_SCOPE, "Fixed narrow scope; strict mode rejects a different requested scope."));
    PluginDescriptor descriptor = new PluginDescriptor("WAI Exact-TTL JWT Access Token Manager", this, gui, "1.0.0");
    descriptor.setAttributeContractSet(CONTRACT); descriptor.setSupportsExtendedContract(true);
    return descriptor;
  }

  private static TextFieldDescriptor requiredField(String name, String description) {
    TextFieldDescriptor field = new TextFieldDescriptor(name, description);
    field.addValidator(new RequiredFieldValidator()); return field;
  }
  private static String required(String value, String name) {
    if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    return value;
  }
	private static boolean isTrustDomain(String value) {
	return value.equals(value.toLowerCase(java.util.Locale.ROOT))
		&& value.matches("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
		&& value.contains(".");
	}
}
