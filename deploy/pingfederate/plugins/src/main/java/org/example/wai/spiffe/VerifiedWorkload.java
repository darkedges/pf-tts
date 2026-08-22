package org.example.wai.spiffe;

import java.time.Instant;

public record VerifiedWorkload(String spiffeId, Instant issuedAt, Instant expiresAt) {}
