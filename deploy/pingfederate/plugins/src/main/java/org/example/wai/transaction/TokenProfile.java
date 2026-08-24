package org.example.wai.transaction;

enum TokenProfile {
  LEGACY("legacy-wai-jwt"),
  TRANSACTION_TOKEN_V11("ietf-txn-token-v11");

  private final String value;

  TokenProfile(String value) {
    this.value = value;
  }

  String value() {
    return value;
  }

  static TokenProfile parse(String value) {
    for (TokenProfile profile : values()) {
      if (profile.value.equals(value)) return profile;
    }
    throw new IllegalArgumentException("Token Profile must be an explicit supported value");
  }
}
