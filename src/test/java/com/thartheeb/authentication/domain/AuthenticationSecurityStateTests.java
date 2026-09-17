package com.thartheeb.authentication.domain;

import static com.thartheeb.authentication.api.AuthContracts.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.thartheeb.authentication.common.ApiException;
import com.thartheeb.authentication.application.AuthenticationService;
import com.thartheeb.authentication.application.port.out.VendorApprovalDelivery;
import com.thartheeb.authentication.config.AuthProperties;
import com.thartheeb.authentication.infrastructure.persistence.UserAccountRepository;
import com.thartheeb.authentication.infrastructure.security.ServiceTokenService;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;

@SpringBootTest
class AuthenticationSecurityStateTests {
    @Autowired AuthenticationService authentication;
    @Autowired ServiceTokenService serviceTokens;
    @Autowired UserAccountRepository users;
    @Autowired AuthProperties properties;
    @MockitoBean VendorApprovalDelivery approvalDelivery;

    @Test
    void userAccessAndRefreshTokensUseTheEightHourPolicy() {
        assertThat(properties.accessTokenTtl()).isEqualTo(Duration.ofHours(8));
        assertThat(properties.refreshTokenTtl()).isEqualTo(Duration.ofHours(8));
    }

    @Test
    void failedPasswordAttemptsPersistAndLockTheAccount() {
        String email = "lock-check@vendor.test";
        approveAndSetPassword(email, "Strong!Password42");

        for (int attempt = 0; attempt < 5; attempt++) {
            assertThatThrownBy(() -> authentication.login(new LoginRequest(email, "Wrong!Password42")))
                .isInstanceOf(ApiException.class);
        }

        UserAccount user = users.findByIdentifierNormalized(email).orElseThrow();
        assertThat(user.getFailedAttempts()).isEqualTo(5);
        assertThat(user.getStatus()).isEqualTo(AuthTypes.AccountStatus.LOCKED);
        assertThat(user.getLockedUntil()).isNotNull();
    }

    @Test
    void approvedVendorSetsPasswordOnceAndLogsInWithoutMfa() {
        String email = "activation-check@vendor.test";
        VendorRegistrationResponse registration =
            authentication.registerVendor(new VendorRegistrationRequest(email));
        assertThat(registration.mfaRequired()).isFalse();
        assertThat(registration.onboardingSession().accessToken()).isNotBlank();

        UUID vendorId = UUID.randomUUID();
        authentication.activateMembership(new ApproveVendorMembershipRequest(
            registration.userId(), vendorId, email, "Activation Test Vendor"));
        authentication.activateMembership(new ApproveVendorMembershipRequest(
            registration.userId(), vendorId, email, "Activation Test Vendor"));
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(approvalDelivery).deliver(eq(email), eq("Activation Test Vendor"),
            token.capture(), any());

        VendorActivationValidationResponse validation =
            authentication.validateVendorActivation(token.getValue());
        assertThat(validation.valid()).isTrue();
        authentication.confirmVendorActivation(new VendorPasswordSetupRequest(
            token.getValue(), "Strong!Password42", "Strong!Password42"));

        LoginResponse login = authentication.login(new LoginRequest(email, "Strong!Password42"));
        assertThat(login.mfaRequired()).isFalse();
        assertThat(login.tokens().accessToken()).isNotBlank();
        assertThatThrownBy(() -> authentication.confirmVendorActivation(
            new VendorPasswordSetupRequest(token.getValue(),
                "Another!Password42", "Another!Password42")))
            .isInstanceOf(ApiException.class);
    }

    @Test
    void serviceTokenRequiresTheRegisteredClientSecret() {
        ServiceTokenResponse token = serviceTokens.issue(
            new ServiceTokenRequest("operations-service", "test-operations-secret"));
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(token.accessToken()).isNotBlank();
        assertThatThrownBy(() -> serviceTokens.issue(
            new ServiceTokenRequest("operations-service", "wrong-secret")))
            .isInstanceOf(ApiException.class);
    }

    private void approveAndSetPassword(String email, String password) {
        VendorRegistrationResponse registration =
            authentication.registerVendor(new VendorRegistrationRequest(email));
        authentication.activateMembership(new ApproveVendorMembershipRequest(
            registration.userId(), UUID.randomUUID(), email, "Lock Test Vendor"));
        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        verify(approvalDelivery).deliver(eq(email), eq("Lock Test Vendor"), token.capture(), any());
        authentication.confirmVendorActivation(
            new VendorPasswordSetupRequest(token.getValue(), password, password));
    }
}
