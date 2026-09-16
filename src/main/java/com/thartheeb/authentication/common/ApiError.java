package com.thartheeb.authentication.common;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.Map;

@Schema(name = "ApiError", description = "Uniform error response returned by every Thartheeb API")
public record ApiError(
    @Schema(example = "404") int status,
    @Schema(example = "Not Found") String error,
    @Schema(example = "User with id 123 not found") String message,
    @Schema(description = "Existing RFC problem type, when supplied") String type,
    @Schema(description = "Existing domain error title, when supplied") String title,
    @Schema(description = "Existing detailed message, when supplied") String detail,
    @Schema(description = "Existing request instance, when supplied") String instance,
    @Schema(description = "Existing stable domain error code, when supplied") String code,
    @Schema(description = "Existing error timestamp, when supplied") Instant timestamp,
    @Schema(description = "Existing field validation errors, when supplied") Map<String, String> errors,
    @Schema(description = "Existing request path, when supplied") String path
) {
}
