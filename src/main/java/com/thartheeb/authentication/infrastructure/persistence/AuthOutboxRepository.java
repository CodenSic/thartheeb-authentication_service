package com.thartheeb.authentication.infrastructure.persistence;

import com.thartheeb.authentication.infrastructure.messaging.AuthOutboxEvent;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthOutboxRepository extends JpaRepository<AuthOutboxEvent, UUID> {
    List<AuthOutboxEvent> findTop50ByPublishedAtIsNullOrderByOccurredAtAsc();
}
