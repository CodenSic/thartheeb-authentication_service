package com.thartheeb.authentication.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_sessions")
public class AuthSession {
    @Id
    private UUID id;
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    @Column(name = "vendor_id")
    private UUID vendorId;
    @Column(name = "mfa_level", nullable = false)
    private int mfaLevel;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected AuthSession() {
    }

    public AuthSession(UUID userId, UUID vendorId, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.vendorId = vendorId;
        this.mfaLevel = 1;
        this.expiresAt = expiresAt;
    }

    public boolean active(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }

    public void revoke(Instant now) {
        if (revokedAt == null) revokedAt = now;
    }

    @PrePersist
    void created() {
        createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getVendorId() { return vendorId; }
    public int getMfaLevel() { return mfaLevel; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
}
