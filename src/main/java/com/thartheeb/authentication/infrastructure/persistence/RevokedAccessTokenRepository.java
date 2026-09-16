package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.domain.RevokedAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RevokedAccessTokenRepository extends JpaRepository<RevokedAccessToken, String> {
}
