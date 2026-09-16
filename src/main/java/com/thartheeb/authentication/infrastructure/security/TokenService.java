package com.thartheeb.authentication.infrastructure.security;

import com.thartheeb.authentication.config.AuthProperties;
import com.thartheeb.authentication.domain.AuthSession;
import com.thartheeb.authentication.domain.TenantMembership;
import com.thartheeb.authentication.domain.UserAccount;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

@Component
public class TokenService {
    private final JwtEncoder encoder;
    private final AuthProperties properties;

    public TokenService(JwtEncoder encoder, AuthProperties properties) {
        this.encoder = encoder;
        this.properties = properties;
    }

    public AccessToken issue(UserAccount user, TenantMembership membership, AuthSession session, Instant now) {
        Instant expiresAt = now.plus(properties.accessTokenTtl());
        String jti = UUID.randomUUID().toString();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
            .issuer(properties.issuer())
            .subject(user.getId().toString())
            .issuedAt(now)
            .expiresAt(expiresAt)
            .id(jti)
            .claim("sid", session.getId().toString())
            .claim("roles", List.of(membership.getRole()))
            .claim("scope", "vendor")
            .claim("mfa_level", session.getMfaLevel())
            .claim("security_version", user.getSecurityVersion());
        if (membership.getVendorId() != null) {
            claims.claim("vendor_id", membership.getVendorId().toString());
        }
        return new AccessToken(encoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue(),
            jti, expiresAt);
    }

    public String issueInternalServiceToken(String serviceName, Instant now) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer(properties.issuer())
            .subject(serviceName)
            .issuedAt(now)
            .expiresAt(now.plus(properties.serviceTokenTtl()))
            .id(UUID.randomUUID().toString())
            .claim("roles", List.of("SERVICE"))
            .claim("scope", "internal")
            .build();
        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public record AccessToken(String value, String jti, Instant expiresAt) {
    }
}
