package com.thartheeb.authentication.common;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(ApiException.class)
    ResponseEntity<ProblemDetail> api(ApiException ex, HttpServletRequest request) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(ex.status(), ex.getMessage());
        detail.setTitle(ex.code());
        detail.setType(URI.create("https://api.thartheeb.qa/problems/" + ex.code().toLowerCase()));
        detail.setProperty("code", ex.code());
        detail.setProperty("error", ex.status().getReasonPhrase());
        detail.setProperty("message", ex.getMessage());
        detail.setInstance(URI.create(request.getRequestURI()));
        return ResponseEntity.status(ex.status()).body(detail);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ProblemDetail> validation(MethodArgumentNotValidException ex,
                                             HttpServletRequest request) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST, "The request contains invalid fields.");
        detail.setTitle("VALIDATION_FAILED");
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
            errors.putIfAbsent(error.getField(), error.getDefaultMessage()));
        detail.setProperty("code", "VALIDATION_FAILED");
        detail.setProperty("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
        detail.setProperty("message", "The request contains invalid fields.");
        detail.setProperty("errors", errors);
        detail.setInstance(URI.create(request.getRequestURI()));
        return ResponseEntity.badRequest().body(detail);
    }
}
