package com.thartheeb.authentication.config;

import java.time.Duration;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "thartheeb.auth")
public record AuthProperties(
    String issuer,
    Duration accessTokenTtl,
    Duration refreshTokenTtl,
    Duration resetTokenTtl,
    Duration vendorActivationTokenTtl,
    String vendorLoginPageUrl,
    Duration mfaChallengeTtl,
    int maximumAttempts,
    Duration lockDuration,
    String fieldEncryptionKeyBase64,
    Map<String, String> serviceClients,
    Duration serviceTokenTtl,
    String signingPrivateKeyPem,
    String signingKeyId,
    boolean allowEphemeralSigningKey
) {
}
