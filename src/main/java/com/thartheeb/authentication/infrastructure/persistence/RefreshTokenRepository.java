package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.RefreshTokenRecord;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenRecord, UUID> {
    Optional<RefreshTokenRecord> findByTokenHash(String tokenHash);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshTokenRecord r where r.tokenHash = :tokenHash")
    Optional<RefreshTokenRecord> findForUpdateByTokenHash(@Param("tokenHash") String tokenHash);
    List<RefreshTokenRecord> findByFamilyId(UUID familyId);
    List<RefreshTokenRecord> findBySessionId(UUID sessionId);
}
