package org.example.wai.transaction;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TrustedTransactionMetadataTest {
  @Test void derivesTrustedValuesAndOverwritesCallerAssertions() {
    AtomicInteger sequence = new AtomicInteger();
    var metadata = new TrustedTransactionMetadata(Map.of(
        "spiffe://example.org/agent/demo", "urn:agent:demo",
        "spiffe://example.org/agent/web-app", "urn:agent:web-app"),
        "system.whoami", () -> "server-id-" + sequence.incrementAndGet());
    Map<String,String> input = new HashMap<>();
    input.put("sub", "user-123"); input.put("workload_id", "spiffe://example.org/agent/demo");
    input.put("agent_id", "urn:agent:forged"); input.put("transaction_id", "caller-chosen");
    var result = metadata.derive(input);
    assertEquals("urn:agent:demo", result.get("agent_id"));
    assertEquals("server-id-1", result.get("agent_instance_id"));
    assertEquals("server-id-2", result.get("transaction_id"));
    assertEquals("system.whoami", result.get("transaction_purpose"));
  }

  @Test void rejectsWrongWorkloadAndUnknownPurpose() {
    var metadata = new TrustedTransactionMetadata(Map.of("spiffe://example.org/agent/demo",
        "urn:agent:demo"), "customer.read", () -> UUID.randomUUID().toString());
    assertThrows(IllegalArgumentException.class,
        () -> metadata.derive(Map.of("workload_id", "spiffe://example.org/agent/other")));
    assertThrows(IllegalArgumentException.class,
        () -> new TrustedTransactionMetadata(Map.of("spiffe://example.org/agent/demo",
            "urn:agent:demo"), "delete.everything", () -> "id"));
  }

  @Test void rejectsMalformedBindings() {
    assertThrows(IllegalArgumentException.class,
        () -> new TrustedTransactionMetadata(Map.of("https://example.org/agent/demo",
            "urn:agent:demo"), "customer.read", () -> "id"));
    assertThrows(IllegalArgumentException.class,
        () -> new TrustedTransactionMetadata(Map.of("spiffe://example.org/agent/demo",
            "admin"), "customer.read", () -> "id"));
    assertThrows(IllegalArgumentException.class,
        () -> new TrustedTransactionMetadata(Map.of(), "customer.read", () -> "id"));
  }

  @Test void resolvesWebWorkloadAndRejectsForgedPair() {
    var metadata = new TrustedTransactionMetadata(Map.of(
        "spiffe://example.org/agent/demo", "urn:agent:demo",
        "spiffe://example.org/agent/web-app", "urn:agent:web-app"),
        "system.whoami", () -> UUID.randomUUID().toString());
    var web = metadata.derive(Map.of("workload_id", "spiffe://example.org/agent/web-app",
        "agent_id", "urn:agent:demo"));
    assertEquals("urn:agent:web-app", web.get("agent_id"));
    assertThrows(IllegalArgumentException.class,
        () -> metadata.derive(Map.of("workload_id", "spiffe://example.org/agent/forged")));
  }
}
