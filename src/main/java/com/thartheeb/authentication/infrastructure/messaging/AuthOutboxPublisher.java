package com.thartheeb.authentication.infrastructure.messaging;

import com.thartheeb.authentication.infrastructure.persistence.AuthOutboxRepository;
import com.thartheeb.authentication.infrastructure.security.TokenService;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

@Component
public class AuthOutboxPublisher {
    private static final Logger log = LoggerFactory.getLogger(AuthOutboxPublisher.class);
    private final AuthOutboxRepository events;
    private final TokenService tokens;
    private final RestClient admin;

    public AuthOutboxPublisher(AuthOutboxRepository events, TokenService tokens,
                               @Value("${thartheeb.admin-service.base-url}") String adminUrl) {
        this.events = events;
        this.tokens = tokens;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(2));
        factory.setReadTimeout(Duration.ofSeconds(3));
        this.admin = RestClient.builder().requestFactory(factory).baseUrl(adminUrl).build();
    }

    @Scheduled(fixedDelayString = "${thartheeb.auth.outbox-publish-delay:PT2S}")
    @Transactional
    public void publish() {
        for (AuthOutboxEvent event : events.findTop50ByPublishedAtIsNullOrderByOccurredAtAsc()) {
            try {
                admin.post().uri("/internal/v1/audit-events")
                    .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + tokens.issueInternalServiceToken("authentication-service", Instant.now()))
                    .body(new AuditRequest("authentication-service", event.getEventType(),
                        event.getAggregateId().toString(), "USER", null, event.getEventType(),
                        "SUCCESS", null, event.getId().toString(), event.getPayloadJson(),
                        event.getOccurredAt()))
                    .retrieve().toBodilessEntity();
                event.markPublished();
            } catch (RuntimeException ex) {
                log.warn("Auth outbox delivery failed for event {} type {}; it will be retried",
                    event.getId(), event.getEventType());
                break;
            }
        }
    }

    private record AuditRequest(String source, String eventType, String actorId, String actorType,
                                String tenantId, String action, String outcome, String reason,
                                String correlationId, String metadataJson, Instant occurredAt) {}
}
