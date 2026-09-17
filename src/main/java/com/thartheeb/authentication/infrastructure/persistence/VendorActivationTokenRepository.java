package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.VendorActivationToken;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface VendorActivationTokenRepository extends JpaRepository<VendorActivationToken, UUID> {
    Optional<VendorActivationToken> findByTokenId(String tokenId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from VendorActivationToken t where t.tokenId = :tokenId")
    Optional<VendorActivationToken> findForUpdateByTokenId(@Param("tokenId") String tokenId);

    List<VendorActivationToken> findByUserIdAndConsumedAtIsNull(UUID userId);
}
