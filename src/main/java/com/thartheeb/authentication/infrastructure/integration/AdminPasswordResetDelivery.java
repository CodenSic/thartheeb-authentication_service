package com.thartheeb.authentication.infrastructure.integration;

import com.thartheeb.authentication.application.port.out.PasswordResetDelivery;
import com.thartheeb.authentication.infrastructure.security.TokenService;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class AdminPasswordResetDelivery implements PasswordResetDelivery {
    private final RestClient client;
    private final TokenService tokens;

    public AdminPasswordResetDelivery(RestClient.Builder builder,
                                      TokenService tokens,
                                      @Value("${thartheeb.admin-service.base-url:http://localhost:8082}")
                                      String adminBaseUrl) {
        this.client = builder.baseUrl(adminBaseUrl).build();
        this.tokens = tokens;
    }

    @Override
    public void deliver(String identifier, String token, Instant expiresAt) {
        client.post()
            .uri("/internal/v1/notifications/password-reset")
            .header(HttpHeaders.AUTHORIZATION,
                "Bearer " + tokens.issueInternalServiceToken("authentication-service", Instant.now()))
            .body(new DeliveryRequest(identifier, token, expiresAt))
            .retrieve()
            .toBodilessEntity();
    }

    private record DeliveryRequest(String identifier, String token, Instant expiresAt) {
    }
}
