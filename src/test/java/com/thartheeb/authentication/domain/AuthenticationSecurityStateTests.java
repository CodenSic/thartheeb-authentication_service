package com.thartheeb.authentication.domain;

import static com.thartheeb.authentication.api.AuthContracts.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.thartheeb.authentication.common.ApiException;
import com.thartheeb.authentication.application.AuthenticationService;
import com.thartheeb.authentication.infrastructure.persistence.UserAccountRepository;
import com.thartheeb.authentication.infrastructure.security.ServiceTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuthenticationSecurityStateTests {
    @Autowired AuthenticationService authentication;
    @Autowired ServiceTokenService serviceTokens;
    @Autowired UserAccountRepository users;

    @Test
    void failedPasswordAttemptsPersistAndLockTheAccount() {
        String email = "lock-check@vendor.test";
        authentication.registerVendor(new VendorRegistrationRequest(email, "Strong!Password42"));

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
    void serviceTokenRequiresTheRegisteredClientSecret() {
        ServiceTokenResponse token = serviceTokens.issue(
            new ServiceTokenRequest("operations-service", "test-operations-secret"));
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(token.accessToken()).isNotBlank();
        assertThatThrownBy(() -> serviceTokens.issue(
            new ServiceTokenRequest("operations-service", "wrong-secret")))
            .isInstanceOf(ApiException.class);
    }
}
