package com.thartheeb.authentication.application.port.out;

import java.time.Instant;

public interface PasswordResetDelivery {
    void deliver(String identifier, String token, Instant expiresAt);
}
