package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.AuthSession;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {
    List<AuthSession> findByUserIdAndRevokedAtIsNull(UUID userId);
}
