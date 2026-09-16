package com.thartheeb.authentication.domain;

import static com.thartheeb.authentication.domain.AuthTypes.AccountStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_accounts")
public class UserAccount {
    @Id
    private UUID id;
    @Column(name = "identifier_normalized", nullable = false, unique = true, length = 254)
    private String identifierNormalized;
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private AccountStatus status;
    @Column(name = "mfa_required", nullable = false)
    private boolean mfaRequired;
    @Column(name = "mfa_secret_encrypted", nullable = false, length = 512)
    private String mfaSecretEncrypted;
    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;
    @Column(name = "locked_until")
    private Instant lockedUntil;
    @Column(name = "security_version", nullable = false)
    private long securityVersion;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
    @Version
    @Column(name = "row_version", nullable = false)
    private long rowVersion;

    protected UserAccount() {
    }

    public UserAccount(String identifierNormalized, String passwordHash, String encryptedMfaSecret) {
        this.id = UUID.randomUUID();
        this.identifierNormalized = identifierNormalized;
        this.passwordHash = passwordHash;
        this.mfaSecretEncrypted = encryptedMfaSecret;
        this.mfaRequired = true;
        this.status = AccountStatus.ACTIVE;
    }

    public boolean isLocked(Instant now) {
        if (status == AccountStatus.LOCKED && lockedUntil != null && !lockedUntil.isAfter(now)) {
            status = AccountStatus.ACTIVE;
            failedAttempts = 0;
            lockedUntil = null;
        }
        return status != AccountStatus.ACTIVE;
    }

    public void authenticationFailed(int maximumAttempts, Duration lockDuration, Instant now) {
        failedAttempts++;
        if (failedAttempts >= maximumAttempts) {
            status = AccountStatus.LOCKED;
            lockedUntil = now.plus(lockDuration);
        }
    }

    public void authenticationSucceeded() {
        failedAttempts = 0;
        lockedUntil = null;
        status = AccountStatus.ACTIVE;
    }

    public void changePassword(String encodedPassword) {
        passwordHash = encodedPassword;
        securityVersion++;
    }

    @PrePersist
    void created() {
        createdAt = Instant.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    void updated() {
        updatedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public String getIdentifierNormalized() { return identifierNormalized; }
    public String getPasswordHash() { return passwordHash; }
    public AccountStatus getStatus() { return status; }
    public boolean isMfaRequired() { return mfaRequired; }
    public String getMfaSecretEncrypted() { return mfaSecretEncrypted; }
    public int getFailedAttempts() { return failedAttempts; }
    public Instant getLockedUntil() { return lockedUntil; }
    public long getSecurityVersion() { return securityVersion; }
}
