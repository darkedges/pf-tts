package org.example.wai.spiffe;

import java.time.Instant;
import org.jose4j.jwt.NumericDate;

final class NumericDateFactory {
  private NumericDateFactory() {}
  static NumericDate from(Instant instant) {
    NumericDate value = NumericDate.fromSeconds(instant.getEpochSecond());
    return value;
  }
}
