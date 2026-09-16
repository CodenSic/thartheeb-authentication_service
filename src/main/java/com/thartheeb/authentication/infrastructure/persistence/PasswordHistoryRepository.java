package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.PasswordHistory;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, UUID> {
    List<PasswordHistory> findTop5ByUserIdOrderByCreatedAtDesc(UUID userId);
}
