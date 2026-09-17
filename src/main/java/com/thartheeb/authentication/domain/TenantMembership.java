package com.thartheeb.authentication.domain;

import static com.thartheeb.authentication.domain.AuthTypes.MembershipStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "tenant_memberships")
public class TenantMembership {
    @Id
    private UUID id;
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    @Column(name = "vendor_id")
    private UUID vendorId;
    @Column(nullable = false, length = 64)
    private String role;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private MembershipStatus status;

    protected TenantMembership() {
    }

    public TenantMembership(UUID userId) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.role = "VENDOR_ONBOARDING_ADMIN";
        this.status = MembershipStatus.ONBOARDING;
    }

    public void activate(UUID vendorId) {
        this.vendorId = vendorId;
        this.role = "VENDOR_ADMIN";
        this.status = MembershipStatus.ACTIVE;
    }

    public void suspend() {
        status = MembershipStatus.SUSPENDED;
    }

    public boolean mayAuthenticate() {
        return status == MembershipStatus.ACTIVE;
    }

    public boolean isOnboarding() { return status == MembershipStatus.ONBOARDING; }

    public boolean isActiveFor(UUID expectedVendorId) {
        return status == MembershipStatus.ACTIVE && expectedVendorId.equals(vendorId);
    }

    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getVendorId() { return vendorId; }
    public String getRole() { return role; }
    public MembershipStatus getStatus() { return status; }
}
