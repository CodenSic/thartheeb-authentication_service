package com.thartheeb.authentication.domain;

public final class AuthTypes {
    private AuthTypes() {
    }

    public enum AccountStatus { PENDING_PASSWORD_SETUP, ACTIVE, LOCKED, DISABLED }
    public enum MembershipStatus { ONBOARDING, ACTIVE, SUSPENDED, REVOKED }
}
