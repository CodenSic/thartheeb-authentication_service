package com.thartheeb.authentication.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class AuthContracts {
    private AuthContracts() {
    }

    public record VendorRegistrationRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(min = 12, max = 128) String password
    ) {
    }

    public record VendorRegistrationResponse(
        UUID userId, String role, String mfaSecret, String mfaEnrollmentUri
    ) {
    }

    public record LoginRequest(
        @NotBlank @Email String identifier,
        @NotBlank String password
    ) {
    }

    public record LoginResponse(boolean mfaRequired, UUID challengeId, Instant expiresAt) {
    }

    public record MfaVerifyRequest(
        @NotNull UUID challengeId,
        @NotBlank @Pattern(regexp = "\\d{6}") String code
    ) {
    }

    public record RefreshRequest(@NotBlank String refreshToken) {
    }

    public record TokenResponse(
        String tokenType, String accessToken, Instant accessTokenExpiresAt,
        String refreshToken, Instant refreshTokenExpiresAt, UUID sessionId
    ) {
    }

    public record PasswordResetRequest(@NotBlank @Email String identifier) {
    }

    public record PasswordResetConfirmRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 12, max = 128) String newPassword
    ) {
    }

    public record GenericResponse(String message) {
    }

    public record ActivateVendorMembershipRequest(@NotNull UUID userId, @NotNull UUID vendorId) {
    }

    public record VendorMembershipStatusRequest(@NotNull UUID vendorId, boolean active) {
    }

    public record IntrospectionRequest(
        @NotBlank String jti, @NotNull UUID sessionId, long securityVersion
    ) {
    }

    public record IntrospectionResponse(boolean active) {
    }

    public record ServiceTokenRequest(@NotBlank String clientId, @NotBlank String clientSecret) {
    }

    public record ServiceTokenResponse(String tokenType, String accessToken, Instant expiresAt) {
    }
}
