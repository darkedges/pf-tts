package org.example.wai.transaction;

import java.security.PrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

public final class TransactionJwtIssuer {
  private static final Set<String> REQUIRED = Set.of("sub", "agent_id", "agent_instance_id",
      "workload_id", "transaction_id", "transaction_purpose");
  private final PrivateKey key;
  private final String keyId;
  private final String issuer;
  private final String audience;
  private final int lifetimeSeconds;
  private final Clock clock;
	private final TokenProfile profile;
	private final String target;
	private final String tool;
	private final String configuredScope;

  public TransactionJwtIssuer(PrivateKey key, String keyId, String issuer, String audience,
      int lifetimeSeconds, Clock clock) {
	this(key, keyId, issuer, audience, lifetimeSeconds, clock, TokenProfile.LEGACY, "unused", "unused", "unused");
	}

	public TransactionJwtIssuer(PrivateKey key, String keyId, String issuer, String audience,
		int lifetimeSeconds, Clock clock, TokenProfile profile, String target, String tool,
		String configuredScope) {
    this.key = java.util.Objects.requireNonNull(key, "key");
    this.keyId = text(keyId, "keyId"); this.issuer = text(issuer, "issuer");
    this.audience = text(audience, "audience"); this.clock = java.util.Objects.requireNonNull(clock, "clock");
    if (lifetimeSeconds < 1 || lifetimeSeconds > 60) throw new IllegalArgumentException("lifetimeSeconds must be 1..60");
    this.lifetimeSeconds = lifetimeSeconds;
	this.profile = java.util.Objects.requireNonNull(profile, "profile");
	this.target = bounded(target, "target");
	this.tool = bounded(tool, "tool");
	this.configuredScope = bounded(configuredScope, "scope");
  }

  public IssuedTransactionToken issue(Map<String, String> attributes, String scope) {
    for (String name : REQUIRED) text(attributes.get(name), name);
	if (profile == TokenProfile.TRANSACTION_TOKEN_V11 && !configuredScope.equals(scope)) {
	  throw new IllegalArgumentException("requested scope does not match the configured transaction scope");
	}
    Instant now = clock.instant(); Instant expiry = now.plusSeconds(lifetimeSeconds);
    try {
      JwtClaims claims = new JwtClaims();
      claims.setIssuer(issuer); claims.setSubject(attributes.get("sub")); claims.setAudience(audience);
      claims.setIssuedAt(NumericDate.fromSeconds(now.getEpochSecond()));
		  if (profile == TokenProfile.LEGACY) claims.setNotBefore(NumericDate.fromSeconds(now.getEpochSecond()));
      claims.setExpirationTime(NumericDate.fromSeconds(expiry.getEpochSecond()));
		  claims.setJwtId(UUID.randomUUID().toString());
		  if (profile == TokenProfile.TRANSACTION_TOKEN_V11) {
			claims.setStringClaim("txn", attributes.get("transaction_id"));
			claims.setStringClaim("scope", configuredScope);
			claims.setStringClaim("req_wl", attributes.get("workload_id"));
			Map<String,Object> agent = Map.of(
				"id", attributes.get("agent_id"),
				"instance_id", attributes.get("agent_instance_id"),
				"workload_id", attributes.get("workload_id"));
			Map<String,Object> wai = Map.of("version", 1, "agent", agent, "target", target, "tool", tool);
			claims.setClaim("tctx", Map.of("wai", wai));
		  } else {
			for (String name : REQUIRED) if (!"sub".equals(name)) claims.setStringClaim(name, attributes.get(name));
			if (scope != null && !scope.isBlank()) claims.setStringClaim("scope", scope);
		  }
      JsonWebSignature signature = new JsonWebSignature();
      signature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		  signature.setKeyIdHeaderValue(keyId);
		  signature.setHeader("typ", profile == TokenProfile.TRANSACTION_TOKEN_V11 ? "txntoken+jwt" : "at+jwt");
      signature.setPayload(claims.toJson()); signature.setKey(key);
      return new IssuedTransactionToken(signature.getCompactSerialization(), expiry.toEpochMilli());
    } catch (Exception e) {
      throw new IllegalStateException("transaction token signing failed", e);
    }
  }

  private static String text(String value, String name) {
    if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    return value;
  }

	private static String bounded(String value, String name) {
		value = text(value, name);
		if (value.length() > 200 || !value.equals(value.trim()) || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
		  throw new IllegalArgumentException(name + " is invalid");
		}
		return value;
	}
}
