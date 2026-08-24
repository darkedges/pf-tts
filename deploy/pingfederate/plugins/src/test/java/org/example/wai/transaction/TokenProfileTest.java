package org.example.wai.transaction;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class TokenProfileTest {
  @Test void requiresAnExplicitKnownProfile() {
    assertEquals(TokenProfile.LEGACY, TokenProfile.parse("legacy-wai-jwt"));
    assertEquals(TokenProfile.TRANSACTION_TOKEN_V11, TokenProfile.parse("ietf-txn-token-v11"));
    assertThrows(IllegalArgumentException.class, () -> TokenProfile.parse("auto"));
    assertThrows(IllegalArgumentException.class, () -> TokenProfile.parse(""));
    assertThrows(IllegalArgumentException.class, () -> TokenProfile.parse(null));
  }
}
