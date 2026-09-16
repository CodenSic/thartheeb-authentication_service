package com.thartheeb.authentication.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_history")
public class PasswordHistory {
    @Id
    private UUID id;
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected PasswordHistory() {
    }

    public PasswordHistory(UUID userId, String passwordHash) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.passwordHash = passwordHash;
    }

    @PrePersist
    void created() {
        createdAt = Instant.now();
    }

    public String getPasswordHash() { return passwordHash; }
}
