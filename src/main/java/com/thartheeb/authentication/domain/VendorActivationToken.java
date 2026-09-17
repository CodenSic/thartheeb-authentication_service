package com.thartheeb.authentication.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "vendor_activation_tokens")
public class VendorActivationToken {
    @Id
    private UUID id;
    @Column(name = "token_id", nullable = false, unique = true, length = 64)
    private String tokenId;
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    @Column(name = "vendor_id", nullable = false)
    private UUID vendorId;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "consumed_at")
    private Instant consumedAt;
    @Version
    @Column(name = "row_version", nullable = false)
    private long rowVersion;

    protected VendorActivationToken() {
    }

    public VendorActivationToken(String tokenId, UUID userId, UUID vendorId, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.tokenId = tokenId;
        this.userId = userId;
        this.vendorId = vendorId;
        this.expiresAt = expiresAt;
    }

    public boolean usable(Instant now, UUID expectedUserId, UUID expectedVendorId) {
        return consumedAt == null && expiresAt.isAfter(now)
            && userId.equals(expectedUserId) && vendorId.equals(expectedVendorId);
    }

    public void consume(Instant now) {
        if (consumedAt == null) consumedAt = now;
    }

    @PrePersist
    void created() {
        createdAt = Instant.now();
    }

    public String getTokenId() { return tokenId; }
    public UUID getUserId() { return userId; }
    public UUID getVendorId() { return vendorId; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getConsumedAt() { return consumedAt; }
}
