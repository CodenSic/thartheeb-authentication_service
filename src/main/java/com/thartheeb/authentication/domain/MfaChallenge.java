package com.thartheeb.authentication.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "mfa_challenges")
public class MfaChallenge {
    @Id
    private UUID id;
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(nullable = false)
    private int attempts;
    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected MfaChallenge() {
    }

    public MfaChallenge(UUID userId, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.expiresAt = expiresAt;
    }

    public boolean usable(Instant now, int maximumAttempts) {
        return consumedAt == null && expiresAt.isAfter(now) && attempts < maximumAttempts;
    }

    public void failed() {
        attempts++;
    }

    public void consume(Instant now) {
        consumedAt = now;
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public Instant getExpiresAt() { return expiresAt; }
    public int getAttempts() { return attempts; }
}
