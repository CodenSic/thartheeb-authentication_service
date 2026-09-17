package com.thartheeb.authentication.application.port.out;

import java.time.Instant;

public interface VendorApprovalDelivery {
    void deliver(String identifier, String companyName, String token, Instant expiresAt);
}
