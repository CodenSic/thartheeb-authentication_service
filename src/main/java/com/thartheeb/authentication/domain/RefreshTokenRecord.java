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
@Table(name = "refresh_tokens")
public class RefreshTokenRecord {
    @Id
    private UUID id;
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;
    @Column(name = "session_id", nullable = false)
    private UUID sessionId;
    @Column(name = "family_id", nullable = false)
    private UUID familyId;
    @Column(name = "rotation_sequence", nullable = false)
    private long rotationSequence;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "used_at")
    private Instant usedAt;
    @Column(name = "revoked_at")
    private Instant revokedAt;
    @Version
    @Column(name = "row_version", nullable = false)
    private long rowVersion;

    protected RefreshTokenRecord() {
    }

    public RefreshTokenRecord(String tokenHash, UUID sessionId, UUID familyId,
                              long rotationSequence, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.tokenHash = tokenHash;
        this.sessionId = sessionId;
        this.familyId = familyId;
        this.rotationSequence = rotationSequence;
        this.expiresAt = expiresAt;
    }

    public boolean usable(Instant now) {
        return usedAt == null && revokedAt == null && expiresAt.isAfter(now);
    }

    public boolean wasUsed() {
        return usedAt != null;
    }

    public void use(Instant now) {
        usedAt = now;
    }

    public void revoke(Instant now) {
        if (revokedAt == null) revokedAt = now;
    }

    @PrePersist
    void created() {
        createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public String getTokenHash() { return tokenHash; }
    public UUID getSessionId() { return sessionId; }
    public UUID getFamilyId() { return familyId; }
    public long getRotationSequence() { return rotationSequence; }
    public Instant getExpiresAt() { return expiresAt; }
}
