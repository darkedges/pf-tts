package org.example.wai.transaction;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

final class TrustedTransactionMetadata {
  private static final Set<String> ALLOWED_PURPOSES = Set.of("customer.read", "system.whoami");
  private final String workloadId;
  private final String agentId;
  private final String purpose;
  private final Supplier<String> idSupplier;

  TrustedTransactionMetadata(String workloadId, String agentId, String purpose,
      Supplier<String> idSupplier) {
    this.workloadId = validateWorkload(workloadId);
    this.agentId = required(agentId, "Logical Agent ID");
    if (!this.agentId.startsWith("urn:agent:") || this.agentId.length() > 200) {
      throw new IllegalArgumentException("Logical Agent ID must be a bounded urn:agent identifier");
    }
    this.purpose = required(purpose, "Transaction Purpose");
    if (!ALLOWED_PURPOSES.contains(this.purpose)) {
      throw new IllegalArgumentException("Transaction Purpose is not allowlisted");
    }
    this.idSupplier = java.util.Objects.requireNonNull(idSupplier, "idSupplier");
  }

  Map<String,String> derive(Map<String,String> verifiedAttributes) {
    String actual = required(verifiedAttributes.get("workload_id"), "workload_id");
    if (!workloadId.equals(actual)) {
      throw new IllegalArgumentException("verified workload is not bound to the configured logical agent");
    }
    Map<String,String> result = new HashMap<>(verifiedAttributes);
    result.put("agent_id", agentId);
    result.put("agent_instance_id", nextId("agent_instance_id"));
    result.put("transaction_id", nextId("transaction_id"));
    result.put("transaction_purpose", purpose);
    return result;
  }

  private String nextId(String name) {
    String value = required(idSupplier.get(), name);
    if (value.length() > 200) throw new IllegalArgumentException(name + " is too long");
    return value;
  }

  private static String validateWorkload(String value) {
    value = required(value, "Allowed Workload SPIFFE ID");
    URI parsed;
    try { parsed = URI.create(value); } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Allowed Workload SPIFFE ID is invalid", e);
    }
    if (!"spiffe".equals(parsed.getScheme()) || parsed.getHost() == null || parsed.getPath().isBlank()
        || parsed.getQuery() != null || parsed.getFragment() != null || parsed.getUserInfo() != null) {
      throw new IllegalArgumentException("Allowed Workload SPIFFE ID is invalid");
    }
    return parsed.toString();
  }

  private static String required(String value, String name) {
    if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    return value;
  }
}
