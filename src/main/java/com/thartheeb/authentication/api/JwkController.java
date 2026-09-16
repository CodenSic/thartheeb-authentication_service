package com.thartheeb.authentication.api;

import com.nimbusds.jose.jwk.RSAKey;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Token verification", description = "Public keys used to verify Thartheeb access tokens")
public class JwkController {
    private final RSAKey rsaKey;

    public JwkController(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "Get JWT verification keys",
        description = "Publishes RSA public keys used by the gateway and resource servers. Private key material is never returned.")
    Map<String, Object> keys() {
        return Map.of("keys", List.of(rsaKey.toPublicJWK().toJSONObject()));
    }
}
