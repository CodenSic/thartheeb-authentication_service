package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.TenantMembership;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantMembershipRepository extends JpaRepository<TenantMembership, UUID> {
    Optional<TenantMembership> findByUserId(UUID userId);
    List<TenantMembership> findByVendorId(UUID vendorId);
}
