package com.thartheeb.authentication.domain;

public final class AuthTypes {
    private AuthTypes() {
    }

    public enum AccountStatus { ACTIVE, LOCKED, DISABLED }
    public enum MembershipStatus { ONBOARDING, ACTIVE, SUSPENDED, REVOKED }
}
