package com.thartheeb.authentication.infrastructure.security;

import static com.thartheeb.authentication.api.AuthContracts.*;

import com.thartheeb.authentication.common.ApiException;
import com.thartheeb.authentication.config.AuthProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class ServiceTokenService {
    private final AuthProperties properties;
    private final TokenService tokens;

    public ServiceTokenService(AuthProperties properties, TokenService tokens) {
        this.properties = properties;
        this.tokens = tokens;
    }

    public ServiceTokenResponse issue(ServiceTokenRequest request) {
        String expectedSecret = properties.serviceClients().get(request.clientId());
        boolean secretMatches = constantTimeEquals(request.clientSecret(), expectedSecret);
        if (expectedSecret == null || !secretMatches) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CLIENT_CREDENTIALS",
                "Service credentials are invalid.");
        }
        Instant now = Instant.now();
        return new ServiceTokenResponse("Bearer",
            tokens.issueInternalServiceToken(request.clientId(), now),
            now.plus(properties.serviceTokenTtl()));
    }

    private static boolean constantTimeEquals(String left, String right) {
        byte[] a = left == null ? new byte[0] : left.getBytes(StandardCharsets.UTF_8);
        byte[] b = right == null ? new byte[0] : right.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }
}
