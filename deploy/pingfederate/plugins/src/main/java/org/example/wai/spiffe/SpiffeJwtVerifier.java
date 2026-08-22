package org.example.wai.spiffe;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Objects;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwx.JsonWebStructure;

/** Validates a SPIRE JWT-SVID without requiring the deliberately absent iss claim. */
public final class SpiffeJwtVerifier {
  private final String audience;
  private final String trustDomain;
  private final Duration maximumLifetime;
  private final Duration clockSkew;
  private final Clock clock;
  private final JwksVerificationKeyResolver keys;
  private final Set<String> keyIds;

  public SpiffeJwtVerifier(String audience, String trustDomain, Duration maximumLifetime,
      Duration clockSkew, Clock clock, List<JsonWebKey> trustedKeys) {
    this.audience = requireText(audience, "audience");
    this.trustDomain = requireText(trustDomain, "trustDomain");
    this.maximumLifetime = positive(maximumLifetime, "maximumLifetime");
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
    if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofSeconds(30)) > 0) {
      throw new IllegalArgumentException("clockSkew must be between zero and 30 seconds");
    }
    this.clock = Objects.requireNonNull(clock, "clock");
    if (trustedKeys == null || trustedKeys.isEmpty()) throw new IllegalArgumentException("trustedKeys are required");
    List<JsonWebKey> immutableKeys = List.copyOf(trustedKeys);
    this.keyIds = new HashSet<>();
    for (JsonWebKey key : immutableKeys) {
      if (key.getKeyId() == null || key.getKeyId().isBlank() || !keyIds.add(key.getKeyId())) {
        throw new IllegalArgumentException("trusted keys require unique non-empty key IDs");
      }
    }
    this.keys = new JwksVerificationKeyResolver(immutableKeys);
  }

  public VerifiedWorkload verify(String compactJwt) throws VerificationException {
    if (compactJwt == null || compactJwt.isBlank()) throw new VerificationException("actor token is missing");
    try {
      String keyId = JsonWebStructure.fromCompactSerialization(compactJwt).getKeyIdHeaderValue();
      if (keyId == null || !keyIds.contains(keyId)) throw new VerificationException("actor token key ID is unknown");
    } catch (VerificationException e) {
      throw e;
    } catch (Exception e) {
      throw new VerificationException("actor token header is invalid", e);
    }
    JwtConsumer consumer = new JwtConsumerBuilder()
        .setRequireExpirationTime().setRequireIssuedAt().setRequireSubject()
        .setExpectedAudience(audience)
        .setAllowedClockSkewInSeconds(Math.toIntExact(clockSkew.toSeconds()))
        .setEvaluationTime(NumericDateFactory.from(clock.instant()))
        .setVerificationKeyResolver(keys)
        .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
            AlgorithmIdentifiers.RSA_USING_SHA256, AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256))
        .build();
    try {
      JwtClaims claims = consumer.processToClaims(compactJwt);
      Instant issuedAt = Instant.ofEpochSecond(claims.getIssuedAt().getValue());
      Instant expiresAt = Instant.ofEpochSecond(claims.getExpirationTime().getValue());
      if (!expiresAt.isAfter(issuedAt) || Duration.between(issuedAt, expiresAt).compareTo(maximumLifetime) > 0) {
        throw new VerificationException("actor token lifetime is invalid");
      }
      String subject = claims.getSubject();
      URI id = URI.create(subject);
      if (!"spiffe".equals(id.getScheme()) || !trustDomain.equals(id.getHost()) || id.getRawQuery() != null
          || id.getRawFragment() != null || id.getUserInfo() != null || id.getPort() != -1
          || id.getPath() == null || id.getPath().isBlank() || "/".equals(id.getPath())) {
        throw new VerificationException("actor subject is not an allowed SPIFFE ID");
      }
      return new VerifiedWorkload(subject, issuedAt, expiresAt);
    } catch (VerificationException e) {
      throw e;
    } catch (Exception e) {
      throw new VerificationException("actor token validation failed", e);
    }
  }

  private static String requireText(String value, String name) {
    if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    return value;
  }
  private static Duration positive(Duration value, String name) {
    if (value == null || value.isZero() || value.isNegative()) throw new IllegalArgumentException(name + " must be positive");
    return value;
  }

  public static final class VerificationException extends Exception {
    public VerificationException(String message) { super(message); }
    public VerificationException(String message, Throwable cause) { super(message, cause); }
  }
}
