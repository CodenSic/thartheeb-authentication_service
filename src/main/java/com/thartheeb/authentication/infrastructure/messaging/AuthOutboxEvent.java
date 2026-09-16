package com.thartheeb.authentication.infrastructure.messaging;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "outbox_events")
public class AuthOutboxEvent {
    @Id
    private UUID id;
    @Column(name = "aggregate_id", nullable = false)
    private UUID aggregateId;
    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;
    @Column(name = "payload_json", nullable = false, columnDefinition = "text")
    private String payloadJson;
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;
    @Column(name = "published_at")
    private Instant publishedAt;

    protected AuthOutboxEvent() {
    }

    public AuthOutboxEvent(UUID aggregateId, String eventType, String payloadJson) {
        this.id = UUID.randomUUID();
        this.aggregateId = aggregateId;
        this.eventType = eventType;
        this.payloadJson = payloadJson;
    }

    @PrePersist
    void created() {
        occurredAt = Instant.now();
    }

    public void markPublished() { publishedAt = Instant.now(); }
    public UUID getId() { return id; }
    public UUID getAggregateId() { return aggregateId; }
    public String getEventType() { return eventType; }
    public String getPayloadJson() { return payloadJson; }
    public Instant getOccurredAt() { return occurredAt; }
}
