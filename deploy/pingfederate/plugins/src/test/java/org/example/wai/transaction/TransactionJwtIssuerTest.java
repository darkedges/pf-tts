package org.example.wai.transaction;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.Test;

class TransactionJwtIssuerTest {
  @Test void issuesExactlyTwentySecondsAndRequiredClaims() throws Exception {
    RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048); key.setKeyId("txn-1");
    Instant now = Instant.parse("2026-08-23T00:00:00Z");
    var issuer = new TransactionJwtIssuer(key.getPrivateKey(), "txn-1", "https://pf.example", "mcp-gateway", 20, Clock.fixed(now, ZoneOffset.UTC));
    var issued = issuer.issue(valid(), "mcp:invoke");
    var claims = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature().setSkipSignatureVerification().build().processToClaims(issued.value());
    assertEquals(20, claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue());
    assertEquals(now.plusSeconds(20).toEpochMilli(), issued.expiresAtMillis());
    assertEquals("urn:agent:demo", claims.getStringClaimValue("agent_id"));
  }

  @Test void rejectsMissingIdentityAndUnsafeLifetime() throws Exception {
    RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048);
    assertThrows(IllegalArgumentException.class, () -> new TransactionJwtIssuer(key.getPrivateKey(), "k", "https://pf.example", "mcp-gateway", 61, Clock.systemUTC()));
    var issuer = new TransactionJwtIssuer(key.getPrivateKey(), "k", "https://pf.example", "mcp-gateway", 20, Clock.systemUTC());
    var attributes = valid(); attributes.remove("workload_id");
    assertThrows(IllegalArgumentException.class, () -> issuer.issue(attributes, "mcp:invoke"));
  }

  private static Map<String,String> valid() {
    Map<String,String> values = new HashMap<>();
    values.put("sub", "user-123"); values.put("agent_id", "urn:agent:demo"); values.put("agent_instance_id", "instance-1");
    values.put("workload_id", "spiffe://example.org/agent/demo"); values.put("transaction_id", "txn-1"); values.put("transaction_purpose", "customer.read");
    return values;
  }
}
