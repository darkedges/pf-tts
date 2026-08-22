package org.example.wai.transaction;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class ExactTtlConfigurationTest {
  @Test void parsesExactBindingsAndRejectsDuplicateOrMalformedEntries() {
    var bindings = TrustedTransactionMetadata.parseBindings(
        "spiffe://example.org/agent/demo=urn:agent:demo\n" +
        "spiffe://example.org/agent/web-app=urn:agent:web-app");
    assertEquals("urn:agent:web-app", bindings.get("spiffe://example.org/agent/web-app"));
    assertThrows(IllegalArgumentException.class, () -> TrustedTransactionMetadata.parseBindings(
        "spiffe://example.org/agent/demo=urn:agent:demo\n" +
        "spiffe://example.org/agent/demo=urn:agent:forged"));
    assertThrows(IllegalArgumentException.class,
        () -> TrustedTransactionMetadata.parseBindings("spiffe://example.org/agent/demo"));
  }
}
