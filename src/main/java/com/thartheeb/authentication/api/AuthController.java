package com.thartheeb.authentication.api;

import static com.thartheeb.authentication.api.AuthContracts.*;

import com.thartheeb.authentication.application.AuthenticationService;
import com.thartheeb.authentication.common.ApiError;
import com.thartheeb.authentication.infrastructure.security.ServiceTokenService;

import jakarta.validation.Valid;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
@Tag(name = "Authentication", description = "Vendor identity, activation, token, session and password recovery")
@ApiResponses({
    @ApiResponse(responseCode = "400", description = "Validation or password policy failure", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(responseCode = "401", description = "Credentials, MFA, token or session rejected", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(responseCode = "403", description = "Required internal scope is missing", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(responseCode = "409", description = "Duplicate account or conflicting security state", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
})
public class AuthController {
    private final AuthenticationService service;
    private final ServiceTokenService serviceTokens;

    public AuthController(AuthenticationService service, ServiceTokenService serviceTokens) {
        this.service = service;
        this.serviceTokens = serviceTokens;
    }

    @PostMapping("/v1/auth/vendor-registration")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a Vendor onboarding identity",
        description = "Creates a password-pending onboarding user and returns an onboarding-only token session. The permanent password is established only after approval.")
    VendorRegistrationResponse register(@Valid @RequestBody VendorRegistrationRequest request) {
        return service.registerVendor(request);
    }

    @PostMapping("/v1/auth/login")
    @Operation(summary = "Start login",
        description = "Validates approved Vendor credentials and directly returns access/refresh tokens with mfaRequired=false. Accounts explicitly configured for MFA receive a challenge instead.")
    LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return service.login(request);
    }

    @PostMapping("/v1/auth/mfa/verify")
    @Operation(summary = "Verify MFA and issue tokens",
        description = "Consumes a six-digit TOTP challenge and returns an eight-hour RSA JWT, rotated eight-hour refresh token and session identifier.")
    TokenResponse verifyMfa(@Valid @RequestBody MfaVerifyRequest request) {
        return service.verifyMfa(request);
    }

    @PostMapping("/v1/auth/token/refresh")
    @Operation(summary = "Rotate a refresh token",
        description = "Consumes the current refresh token and returns a new access/refresh pair. Reuse revokes the entire token family and session.")
    TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return service.refresh(request);
    }

    @PostMapping("/v1/auth/password-resets")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(summary = "Request a password reset",
        description = "Always returns the same accepted message to prevent account enumeration. Recognized accounts receive a single-use, expiring reset link.")
    GenericResponse requestReset(@Valid @RequestBody PasswordResetRequest request) {
        return service.requestPasswordReset(request);
    }

    @PostMapping("/v1/auth/password-resets/confirm")
    @Operation(summary = "Confirm a password reset",
        description = "Consumes the reset token, enforces password policy/history and revokes all existing sessions.")
    GenericResponse confirmReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
        return service.confirmPasswordReset(request);
    }

    @GetMapping("/v1/auth/vendor-activations/validate")
    @Operation(summary = "Validate a Vendor password-setup link",
        description = "Validates the signed, single-use, 30-minute setup JWT before the frontend displays the set-password form.")
    VendorActivationValidationResponse validateVendorActivation(@RequestParam String token) {
        return service.validateVendorActivation(token);
    }

    @PostMapping("/v1/auth/vendor-activations/confirm")
    @Operation(summary = "Set the approved Vendor password",
        description = "Confirms matching passwords, consumes the one-time setup JWT and enables normal password login without Vendor MFA.")
    VendorPasswordSetupResponse confirmVendorActivation(
        @Valid @RequestBody VendorPasswordSetupRequest request) {
        return service.confirmVendorActivation(request);
    }

    @PostMapping("/v1/auth/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Log out the current session",
        description = "Revokes the session, its refresh tokens and the current access-token JTI.",
        security = @SecurityRequirement(name = "bearerAuth"))
    void logout(JwtAuthenticationToken authentication) {
        UUID sessionId = UUID.fromString(authentication.getToken().getClaimAsString("sid"));
        String jti = authentication.getToken().getId();
        Instant expiresAt = authentication.getToken().getExpiresAt();
        service.logout(sessionId, jti, expiresAt);
    }

    @PostMapping("/v1/auth/logout-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Log out all sessions",
        description = "Revokes every active session and refresh token for the authenticated user.",
        security = @SecurityRequirement(name = "bearerAuth"))
    void logoutAll(JwtAuthenticationToken authentication) {
        service.logoutAll(UUID.fromString(authentication.getToken().getSubject()));
    }

    @PostMapping("/internal/v1/vendor-memberships/activate")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Activate a Vendor membership", tags = "Internal authentication",
        description = "Private idempotent-style integration used after Vendor approval to attach the onboarding user to the active Vendor.",
        security = @SecurityRequirement(name = "bearerAuth"))
    void activate(@Valid @RequestBody ApproveVendorMembershipRequest request) {
        service.activateMembership(request);
    }

    @PostMapping("/internal/v1/vendor-memberships/suspend")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Suspend one Vendor membership", tags = "Internal authentication",
        description = "Private integration that suspends membership and revokes the user's active sessions.",
        security = @SecurityRequirement(name = "bearerAuth"))
    void suspend(@Valid @RequestBody ActivateVendorMembershipRequest request) {
        service.suspendMembership(request);
    }

    @PostMapping("/internal/v1/vendor-memberships/vendor-status")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Apply Vendor status to all memberships", tags = "Internal authentication",
        description = "Activates or suspends every membership for a Vendor; suspension also revokes sessions.",
        security = @SecurityRequirement(name = "bearerAuth"))
    void vendorStatus(@Valid @RequestBody VendorMembershipStatusRequest request) {
        service.changeVendorMembershipStatus(request);
    }

    @PostMapping("/internal/v1/tokens/introspect")
    @Operation(summary = "Introspect token session state", tags = "Internal authentication",
        description = "Checks access-token JTI revocation, session validity, user lock state and security version.",
        security = @SecurityRequirement(name = "bearerAuth"))
    IntrospectionResponse introspect(@Valid @RequestBody IntrospectionRequest request) {
        return service.introspect(request);
    }

    @PostMapping("/v1/auth/service-token")
    @Operation(summary = "Issue an internal service token", tags = "Internal authentication",
        description = "Private-network client-credentials exchange. This path is explicitly denied by the public gateway.")
    ServiceTokenResponse serviceToken(@Valid @RequestBody ServiceTokenRequest request) {
        return serviceTokens.issue(request);
    }
}
