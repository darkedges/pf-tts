package org.example.wai.spiffe;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.List;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SpiffeJwtVerifierTest {
  private static final Instant NOW = Instant.parse("2026-08-23T00:00:00Z");
  private RsaJsonWebKey key;

  @BeforeEach void setUp() throws Exception { key = RsaJwkGenerator.generateJwk(2048); key.setKeyId("key-1"); }

  @Test void acceptsValidIssuerlessJwtSvid() throws Exception {
    var result = verifier(key).verify(token(key, "spiffe://example.org/agent/demo", "pf-audience", NOW.minusSeconds(1), NOW.plusSeconds(29)));
    assertEquals("spiffe://example.org/agent/demo", result.spiffeId());
  }

  @Test void rejectsSecurityFailures() throws Exception {
    RsaJsonWebKey other = RsaJwkGenerator.generateJwk(2048); other.setKeyId("other");
    assertAll(
        () -> assertThrows(SpiffeJwtVerifier.VerificationException.class, () -> verifier(key).verify(token(other, "spiffe://example.org/agent/demo", "pf-audience", NOW, NOW.plusSeconds(30)))),
        () -> assertThrows(SpiffeJwtVerifier.VerificationException.class, () -> verifier(key).verify(token(key, "spiffe://example.org/agent/demo", "wrong", NOW, NOW.plusSeconds(30)))),
        () -> assertThrows(SpiffeJwtVerifier.VerificationException.class, () -> verifier(key).verify(token(key, "spiffe://evil.example/agent/demo", "pf-audience", NOW, NOW.plusSeconds(30)))),
        () -> assertThrows(SpiffeJwtVerifier.VerificationException.class, () -> verifier(key).verify(token(key, "spiffe://example.org/agent/demo", "pf-audience", NOW, NOW.plusSeconds(301)))),
        () -> assertThrows(SpiffeJwtVerifier.VerificationException.class, () -> verifier(key).verify(token(key, "not-a-spiffe-id", "pf-audience", NOW, NOW.plusSeconds(30)))));
  }

  private SpiffeJwtVerifier verifier(RsaJsonWebKey trusted) {
    return new SpiffeJwtVerifier("pf-audience", "example.org", Duration.ofMinutes(5), Duration.ofSeconds(2), Clock.fixed(NOW, ZoneOffset.UTC), List.of(trusted));
  }

  private static String token(RsaJsonWebKey signingKey, String sub, String aud, Instant iat, Instant exp) throws Exception {
    JwtClaims claims = new JwtClaims();
    claims.setSubject(sub); claims.setAudience(aud); claims.setIssuedAt(NumericDateFactory.from(iat)); claims.setExpirationTime(NumericDateFactory.from(exp));
    JsonWebSignature jws = new JsonWebSignature(); jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jws.setKeyIdHeaderValue(signingKey.getKeyId()); jws.setPayload(claims.toJson()); jws.setKey(signingKey.getPrivateKey());
    return jws.getCompactSerialization();
  }
}
