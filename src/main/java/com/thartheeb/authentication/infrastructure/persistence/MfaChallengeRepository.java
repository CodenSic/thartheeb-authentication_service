package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.MfaChallenge;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MfaChallengeRepository extends JpaRepository<MfaChallenge, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from MfaChallenge c where c.id = :id")
    Optional<MfaChallenge> findForUpdate(@Param("id") UUID id);
}
