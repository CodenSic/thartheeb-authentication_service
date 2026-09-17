package com.thartheeb.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest
class OpenApiCoverageTests {
    @Autowired
    private WebApplicationContext context;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = webAppContextSetup(context).build();
    }

    @Test
    void separatesPublicAndInternalAuthenticationApis() throws Exception {
        String publicSpec = getSpec("/v3/api-docs/public");
        assertThat(publicSpec)
                .contains("/v1/auth/vendor-registration")
                .contains("/v1/auth/vendor-activations/validate")
                .contains("/v1/auth/vendor-activations/confirm")
                .contains("/v1/auth/logout")
                .contains("/.well-known/jwks.json")
                .contains("#/components/schemas/ApiError")
                .contains("\"status\"")
                .contains("\"error\"")
                .contains("\"message\"")
                .doesNotContain("/internal/v1/vendor-memberships/activate")
                .doesNotContain("/v1/auth/service-token");
        String internalSpec = getSpec("/v3/api-docs/internal");
        assertThat(internalSpec)
                .contains("/internal/v1/vendor-memberships/activate")
                .contains("/internal/v1/tokens/introspect")
                .contains("/v1/auth/service-token")
                .contains("#/components/schemas/ApiError")
                .doesNotContain("/v1/auth/vendor-registration");
    }

    @Test
    void returnsUniformErrorFieldsAndPreservesExistingProblemFields() throws Exception {
        mvc.perform(post("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"missing@example.qa\",\"password\":\"WrongPassword123*\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.error").value("Unauthorized"))
            .andExpect(jsonPath("$.message").value("The supplied credentials are invalid."))
            .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
            .andExpect(jsonPath("$.detail").value("The supplied credentials are invalid."));
    }

    private String getSpec(String path) throws Exception {
        return mvc.perform(get(path)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString();
    }
}
