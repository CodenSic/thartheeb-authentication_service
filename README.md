# authentication-service

Standalone Spring Boot project for Tartheeb.

Purpose: Handles authentication, users, roles, permissions, tokens, and tenant context.

## Technology

- Java 21
- Spring Boot 4.1.1
- Spring Web MVC
- Spring Validation
- Spring Boot Actuator

## Run

```powershell
mvn spring-boot:run
```

The application starts on port `8081`. Epic-01 implements Vendor onboarding identities, Argon2 passwords, TOTP MFA, JWT/JWK issuance, rotating refresh tokens, password reset, logout/revocation, lockout, service credentials, and audit outbox delivery.
