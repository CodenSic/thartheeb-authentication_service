package com.thartheeb.authentication.common;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import java.util.Map;
import org.springdoc.core.customizers.GlobalOpenApiCustomizer;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.ProblemDetail;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@RestControllerAdvice
public class SuccessResponseAdvice implements ResponseBodyAdvice<Object> {
    @Override
    public boolean supports(MethodParameter returnType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return returnType.getParameterType() != String.class;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        int status = status(response);
        String path = request.getURI().getPath();
        if (!isJson(selectedContentType) || excluded(path) || status < 200 || status >= 300
            || status == HttpStatus.NO_CONTENT.value() || body instanceof ProblemDetail
            || body instanceof SuccessResponse<?>) {
            return body;
        }
        return new SuccessResponse<>(HttpStatus.OK.value(), body);
    }

    private static int status(ServerHttpResponse response) {
        if (response instanceof ServletServerHttpResponse servletResponse) {
            return servletResponse.getServletResponse().getStatus();
        }
        return HttpStatus.OK.value();
    }

    private static boolean isJson(MediaType mediaType) {
        return mediaType != null && (MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)
            || mediaType.getSubtype().endsWith("+json"));
    }

    private static boolean excluded(String path) {
        return path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui")
            || path.startsWith("/actuator") || path.equals("/.well-known/jwks.json");
    }

    public record SuccessResponse<T>(int status, T data) {
    }
}

@Component
final class SuccessResponseOpenApiCustomizer implements GlobalOpenApiCustomizer {
    @Override
    public void customise(OpenAPI openApi) {
        if (openApi.getPaths() == null) return;
        openApi.getPaths().values().forEach(path -> path.readOperations().forEach(operation ->
            operation.getResponses().forEach((code, apiResponse) -> {
                int status = status(code);
                if (status < 200 || status >= 300 || status == 204
                    || apiResponse.getContent() == null) return;
                apiResponse.getContent().forEach((mediaType, content) -> {
                    if (!mediaType.contains("json") || content.getSchema() == null
                        || wrapped(content.getSchema())) return;
                    Schema<?> original = content.getSchema();
                    ObjectSchema envelope = new ObjectSchema();
                    envelope.setDescription("Uniform successful JSON response");
                    envelope.addProperty("status", new IntegerSchema().example(200));
                    envelope.addProperty("data", original);
                    envelope.addExtension("x-thartheeb-success-envelope", true);
                    content.setSchema(envelope);
                });
            })));
    }

    private static boolean wrapped(Schema<?> schema) {
        Map<String, Object> extensions = schema.getExtensions();
        return extensions != null
            && Boolean.TRUE.equals(extensions.get("x-thartheeb-success-envelope"));
    }

    private static int status(String code) {
        try {
            return Integer.parseInt(code);
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

}
