package com.thartheeb.authentication.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(info = @Info(title = "Thartheeb Authentication API", version = "v1",
    description = "Vendor identity, approval activation, token, session, password-reset and internal membership APIs.",
    contact = @Contact(name = "Thartheeb Engineering"),
    license = @License(name = "Proprietary - Internal Use")))
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer",
    bearerFormat = "JWT", description = "RSA-signed user or internal-service access token")
public class OpenApiConfig {
    @Bean GroupedOpenApi publicAuthenticationApi() {
        return GroupedOpenApi.builder().group("public")
            .pathsToMatch("/v1/auth/**", "/.well-known/jwks.json")
            .pathsToExclude("/v1/auth/service-token").build();
    }

    @Bean GroupedOpenApi internalAuthenticationApi() {
        return GroupedOpenApi.builder().group("internal")
            .pathsToMatch("/internal/**", "/v1/auth/service-token").build();
    }
}
