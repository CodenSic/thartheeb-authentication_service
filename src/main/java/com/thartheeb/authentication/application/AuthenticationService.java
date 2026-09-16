package com.thartheeb.authentication.application;

import static com.thartheeb.authentication.api.AuthContracts.*;
import static com.thartheeb.authentication.infrastructure.security.SecureTokens.randomToken;
import static com.thartheeb.authentication.infrastructure.security.SecureTokens.sha256;

import com.thartheeb.authentication.application.port.out.PasswordResetDelivery;
import com.thartheeb.authentication.common.ApiException;
import com.thartheeb.authentication.config.AuthProperties;
import com.thartheeb.authentication.domain.*;
import com.thartheeb.authentication.infrastructure.persistence.*;
import com.thartheeb.authentication.infrastructure.messaging.AuthOutboxEvent;
import com.thartheeb.authentication.infrastructure.security.SecretProtector;
import com.thartheeb.authentication.infrastructure.security.TokenService;
import com.thartheeb.authentication.infrastructure.security.TotpService;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationService {
    private static final String GENERIC_AUTH_MESSAGE = "The supplied credentials are invalid.";
    private static final String GENERIC_RESET_MESSAGE =
        "If the account is recognized, password reset instructions will be sent.";

    private final UserAccountRepository users;
    private final TenantMembershipRepository memberships;
    private final MfaChallengeRepository challenges;
    private final AuthSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final PasswordHistoryRepository passwordHistory;
    private final RevokedAccessTokenRepository revokedAccessTokens;
    private final AuthOutboxRepository outbox;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totp;
    private final SecretProtector secrets;
    private final TokenService tokens;
    private final PasswordResetDelivery resetDelivery;
    private final AuthProperties properties;
    private final String dummyPasswordHash;

    public AuthenticationService(
        UserAccountRepository users,
        TenantMembershipRepository memberships,
        MfaChallengeRepository challenges,
        AuthSessionRepository sessions,
        RefreshTokenRepository refreshTokens,
        PasswordResetTokenRepository resetTokens,
        PasswordHistoryRepository passwordHistory,
        RevokedAccessTokenRepository revokedAccessTokens,
        AuthOutboxRepository outbox,
        PasswordEncoder passwordEncoder,
        TotpService totp,
        SecretProtector secrets,
        TokenService tokens,
        PasswordResetDelivery resetDelivery,
        AuthProperties properties
    ) {
        this.users = users;
        this.memberships = memberships;
        this.challenges = challenges;
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.resetTokens = resetTokens;
        this.passwordHistory = passwordHistory;
        this.revokedAccessTokens = revokedAccessTokens;
        this.outbox = outbox;
        this.passwordEncoder = passwordEncoder;
        this.totp = totp;
        this.secrets = secrets;
        this.tokens = tokens;
        this.resetDelivery = resetDelivery;
        this.properties = properties;
        this.dummyPasswordHash = passwordEncoder.encode("Timing-Only-Password-Value-42!");
    }

    @Transactional
    public VendorRegistrationResponse registerVendor(VendorRegistrationRequest request) {
        String identifier = normalize(request.email());
        if (users.existsByIdentifierNormalized(identifier)) {
            throw new ApiException(HttpStatus.CONFLICT, "ACCOUNT_ALREADY_EXISTS",
                "An account already exists for this identifier.");
        }
        validatePassword(request.password(), identifier);
        String secret = totp.generateSecret();
        String encodedPassword = passwordEncoder.encode(request.password());
        UserAccount user;
        try {
            user = users.saveAndFlush(new UserAccount(
                identifier, encodedPassword, secrets.encrypt(secret)));
        } catch (DataIntegrityViolationException ex) {
            throw new ApiException(HttpStatus.CONFLICT, "ACCOUNT_ALREADY_EXISTS",
                "An account already exists for this identifier.");
        }
        memberships.save(new TenantMembership(user.getId()));
        passwordHistory.save(new PasswordHistory(user.getId(), encodedPassword));
        event(user.getId(), "VendorOnboardingIdentityCreated",
            "{\"userId\":\"" + user.getId() + "\",\"role\":\"VENDOR_ONBOARDING_ADMIN\"}");
        String issuer = URLEncoder.encode("Thartheeb", StandardCharsets.UTF_8);
        String account = URLEncoder.encode(identifier, StandardCharsets.UTF_8);
        String uri = "otpauth://totp/" + issuer + ":" + account + "?secret=" + secret
            + "&issuer=" + issuer + "&digits=6&period=30";
        return new VendorRegistrationResponse(
            user.getId(), "VENDOR_ONBOARDING_ADMIN", secret, uri);
    }

    @Transactional(noRollbackFor = ApiException.class)
    public LoginResponse login(LoginRequest request) {
        Instant now = Instant.now();
        UserAccount user = users.findForUpdateByIdentifier(normalize(request.identifier()))
            .orElse(null);
        if (user == null) {
            passwordEncoder.matches(request.password(), dummyPasswordHash);
            throw unauthorized("INVALID_CREDENTIALS", GENERIC_AUTH_MESSAGE);
        }
        TenantMembership membership = memberships.findByUserId(user.getId()).orElse(null);
        if (user.isLocked(now) || membership == null || !membership.mayAuthenticate()) {
            throw unauthorized("ACCOUNT_UNAVAILABLE", GENERIC_AUTH_MESSAGE);
        }
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            user.authenticationFailed(properties.maximumAttempts(), properties.lockDuration(), now);
            event(user.getId(), "AuthenticationFailed",
                "{\"userId\":\"" + user.getId() + "\"}");
            throw unauthorized("INVALID_CREDENTIALS", GENERIC_AUTH_MESSAGE);
        }
        user.authenticationSucceeded();
        MfaChallenge challenge = challenges.save(
            new MfaChallenge(user.getId(), now.plus(properties.mfaChallengeTtl())));
        return new LoginResponse(true, challenge.getId(), challenge.getExpiresAt());
    }

    @Transactional(noRollbackFor = ApiException.class)
    public TokenResponse verifyMfa(MfaVerifyRequest request) {
        Instant now = Instant.now();
        MfaChallenge challenge = challenges.findForUpdate(request.challengeId())
            .orElseThrow(() -> unauthorized("MFA_CHALLENGE_INVALID", "The MFA challenge is invalid."));
        if (!challenge.usable(now, properties.maximumAttempts())) {
            throw unauthorized("MFA_CHALLENGE_INVALID", "The MFA challenge is invalid or expired.");
        }
        UserAccount user = users.findById(challenge.getUserId())
            .orElseThrow(() -> unauthorized("MFA_CHALLENGE_INVALID", "The MFA challenge is invalid."));
        if (user.isLocked(now) || !totp.verify(
            secrets.decrypt(user.getMfaSecretEncrypted()), request.code(), now)) {
            challenge.failed();
            user.authenticationFailed(properties.maximumAttempts(), properties.lockDuration(), now);
            event(user.getId(), "MfaVerificationFailed",
                "{\"userId\":\"" + user.getId() + "\",\"attempts\":" + challenge.getAttempts() + "}");
            throw unauthorized("MFA_CODE_INVALID", "The MFA code is invalid.");
        }
        TenantMembership membership = membership(user.getId());
        if (!membership.mayAuthenticate()) {
            throw unauthorized("MEMBERSHIP_INACTIVE", GENERIC_AUTH_MESSAGE);
        }
        challenge.consume(now);
        user.authenticationSucceeded();
        AuthSession session = sessions.save(new AuthSession(
            user.getId(), membership.getVendorId(), now.plus(properties.refreshTokenTtl())));
        return issueTokenPair(user, membership, session, UUID.randomUUID(), 0, now);
    }

    @Transactional(noRollbackFor = ApiException.class)
    public TokenResponse refresh(RefreshRequest request) {
        Instant now = Instant.now();
        RefreshTokenRecord current = refreshTokens.findForUpdateByTokenHash(sha256(request.refreshToken()))
            .orElseThrow(() -> unauthorized("REFRESH_TOKEN_INVALID", "The refresh token is invalid."));
        AuthSession session = sessions.findById(current.getSessionId())
            .orElseThrow(() -> unauthorized("SESSION_INVALID", "The session is invalid."));
        if (current.wasUsed()) {
            revokeFamily(current.getFamilyId(), now);
            session.revoke(now);
            event(session.getUserId(), "RefreshTokenReuseDetected",
                "{\"userId\":\"" + session.getUserId() + "\",\"sessionId\":\"" + session.getId() + "\"}");
            throw unauthorized("REFRESH_TOKEN_REUSED", "Refresh token reuse was detected.");
        }
        if (!current.usable(now) || !session.active(now)) {
            throw unauthorized("REFRESH_TOKEN_INVALID", "The refresh token is invalid or expired.");
        }
        UserAccount user = users.findById(session.getUserId())
            .orElseThrow(() -> unauthorized("ACCOUNT_UNAVAILABLE", GENERIC_AUTH_MESSAGE));
        TenantMembership membership = membership(user.getId());
        if (user.isLocked(now) || !membership.mayAuthenticate()) {
            revokeSession(session, now);
            throw unauthorized("ACCOUNT_UNAVAILABLE", GENERIC_AUTH_MESSAGE);
        }
        current.use(now);
        return issueTokenPair(user, membership, session, current.getFamilyId(),
            current.getRotationSequence() + 1, now);
    }

    @Transactional
    public GenericResponse requestPasswordReset(PasswordResetRequest request) {
        users.findByIdentifierNormalized(normalize(request.identifier())).ifPresent(user -> {
            Instant expiresAt = Instant.now().plus(properties.resetTokenTtl());
            String token = randomToken();
            resetTokens.save(new PasswordResetToken(user.getId(), sha256(token), expiresAt));
            try {
                resetDelivery.deliver(user.getIdentifierNormalized(), token, expiresAt);
            } catch (RuntimeException ignored) {
                event(user.getId(), "PasswordResetDeliveryFailed",
                    "{\"userId\":\"" + user.getId() + "\"}");
            }
        });
        return new GenericResponse(GENERIC_RESET_MESSAGE);
    }

    @Transactional
    public GenericResponse confirmPasswordReset(PasswordResetConfirmRequest request) {
        Instant now = Instant.now();
        PasswordResetToken reset = resetTokens.findForUpdateByTokenHash(sha256(request.token()))
            .orElseThrow(() -> unauthorized("RESET_TOKEN_INVALID", "The reset token is invalid or expired."));
        if (!reset.usable(now)) {
            throw unauthorized("RESET_TOKEN_INVALID", "The reset token is invalid or expired.");
        }
        UserAccount user = users.findById(reset.getUserId())
            .orElseThrow(() -> unauthorized("RESET_TOKEN_INVALID", "The reset token is invalid or expired."));
        validatePassword(request.newPassword(), user.getIdentifierNormalized());
        boolean reused = passwordHistory.findTop5ByUserIdOrderByCreatedAtDesc(user.getId()).stream()
            .anyMatch(history -> passwordEncoder.matches(
                request.newPassword(), history.getPasswordHash()));
        if (reused) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "PASSWORD_REUSED",
                "The new password cannot match a recent password.");
        }
        String encoded = passwordEncoder.encode(request.newPassword());
        user.changePassword(encoded);
        passwordHistory.save(new PasswordHistory(user.getId(), encoded));
        reset.consume(now);
        revokeAllSessions(user.getId(), now);
        event(user.getId(), "PasswordResetCompleted",
            "{\"userId\":\"" + user.getId() + "\"}");
        return new GenericResponse("Password reset completed. Sign in again.");
    }

    @Transactional
    public void logout(UUID sessionId, String jti, Instant accessTokenExpiry) {
        Instant now = Instant.now();
        sessions.findById(sessionId).ifPresent(session -> revokeSession(session, now));
        revokedAccessTokens.save(new RevokedAccessToken(jti, accessTokenExpiry, now));
        event(sessionId, "SessionRevoked",
            "{\"sessionId\":\"" + sessionId + "\"}");
    }

    @Transactional
    public void logoutAll(UUID userId) {
        revokeAllSessions(userId, Instant.now());
        event(userId, "AllSessionsRevoked", "{\"userId\":\"" + userId + "\"}");
    }

    @Transactional
    public void activateMembership(ActivateVendorMembershipRequest request) {
        TenantMembership membership = memberships.findByUserId(request.userId())
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "MEMBERSHIP_NOT_FOUND",
                "Vendor membership was not found."));
        membership.activate(request.vendorId());
        event(request.userId(), "VendorMembershipActivated",
            "{\"userId\":\"" + request.userId() + "\",\"vendorId\":\"" + request.vendorId() + "\"}");
    }

    @Transactional
    public void suspendMembership(ActivateVendorMembershipRequest request) {
        TenantMembership membership = memberships.findByUserId(request.userId())
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "MEMBERSHIP_NOT_FOUND",
                "Vendor membership was not found."));
        membership.suspend();
        revokeAllSessions(request.userId(), Instant.now());
    }

    @Transactional
    public void changeVendorMembershipStatus(VendorMembershipStatusRequest request) {
        Instant now = Instant.now();
        memberships.findByVendorId(request.vendorId()).forEach(membership -> {
            if (request.active()) {
                membership.activate(request.vendorId());
            } else {
                membership.suspend();
                revokeAllSessions(membership.getUserId(), now);
            }
        });
        event(request.vendorId(), request.active() ? "VendorMembershipsActivated"
            : "VendorMembershipsSuspended", "{\"vendorId\":\"" + request.vendorId()
            + "\",\"active\":" + request.active() + "}");
    }

    @Transactional(readOnly = true)
    public IntrospectionResponse introspect(IntrospectionRequest request) {
        if (revokedAccessTokens.existsById(request.jti())) return new IntrospectionResponse(false);
        AuthSession session = sessions.findById(request.sessionId()).orElse(null);
        if (session == null || !session.active(Instant.now())) return new IntrospectionResponse(false);
        UserAccount user = users.findById(session.getUserId()).orElse(null);
        return new IntrospectionResponse(user != null
            && user.getSecurityVersion() == request.securityVersion()
            && !user.isLocked(Instant.now()));
    }

    private TokenResponse issueTokenPair(UserAccount user, TenantMembership membership,
                                         AuthSession session, UUID familyId,
                                         long sequence, Instant now) {
        String rawRefresh = randomToken();
        RefreshTokenRecord refresh = refreshTokens.save(new RefreshTokenRecord(
            sha256(rawRefresh), session.getId(), familyId, sequence,
            now.plus(properties.refreshTokenTtl())));
        TokenService.AccessToken access = tokens.issue(user, membership, session, now);
        return new TokenResponse("Bearer", access.value(), access.expiresAt(), rawRefresh,
            refresh.getExpiresAt(), session.getId());
    }

    private void revokeAllSessions(UUID userId, Instant now) {
        sessions.findByUserIdAndRevokedAtIsNull(userId).forEach(session -> revokeSession(session, now));
    }

    private void revokeSession(AuthSession session, Instant now) {
        session.revoke(now);
        refreshTokens.findBySessionId(session.getId()).forEach(token -> token.revoke(now));
    }

    private void revokeFamily(UUID familyId, Instant now) {
        refreshTokens.findByFamilyId(familyId).forEach(token -> token.revoke(now));
    }

    private TenantMembership membership(UUID userId) {
        return memberships.findByUserId(userId)
            .orElseThrow(() -> unauthorized("MEMBERSHIP_INACTIVE", GENERIC_AUTH_MESSAGE));
    }

    private void validatePassword(String password, String identifier) {
        boolean valid = password.length() >= 12
            && password.chars().anyMatch(Character::isUpperCase)
            && password.chars().anyMatch(Character::isLowerCase)
            && password.chars().anyMatch(Character::isDigit)
            && password.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch))
            && !password.toLowerCase(Locale.ROOT).contains(
                identifier.substring(0, Math.min(identifier.indexOf('@') > 0
                    ? identifier.indexOf('@') : identifier.length(), 4)).toLowerCase(Locale.ROOT));
        if (!valid) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "PASSWORD_POLICY_FAILED",
                "Password must contain at least 12 characters with upper, lower, number and symbol.");
        }
    }

    private void event(UUID aggregateId, String type, String payload) {
        outbox.save(new AuthOutboxEvent(aggregateId, type, payload));
    }

    private static String normalize(String identifier) {
        return identifier.trim().toLowerCase(Locale.ROOT);
    }

    private static ApiException unauthorized(String code, String message) {
        return new ApiException(HttpStatus.UNAUTHORIZED, code, message);
    }
}
