package com.thartheeb.authentication.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "revoked_access_tokens")
public class RevokedAccessToken {
    @Id
    @Column(length = 64)
    private String jti;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt;

    protected RevokedAccessToken() {
    }

    public RevokedAccessToken(String jti, Instant expiresAt, Instant revokedAt) {
        this.jti = jti;
        this.expiresAt = expiresAt;
        this.revokedAt = revokedAt;
    }
}
