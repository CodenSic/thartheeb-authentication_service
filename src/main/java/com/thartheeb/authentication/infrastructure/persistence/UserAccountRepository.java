package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.UserAccount;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserAccountRepository extends JpaRepository<UserAccount, UUID> {
    Optional<UserAccount> findByIdentifierNormalized(String identifierNormalized);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from UserAccount u where u.identifierNormalized = :identifier")
    Optional<UserAccount> findForUpdateByIdentifier(@Param("identifier") String identifier);
    boolean existsByIdentifierNormalized(String identifierNormalized);
}
