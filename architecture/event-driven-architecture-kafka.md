# Event-Driven Architecture (Kafka)

This document explains how Kafka is used as the real-time event backbone for detection, alerting, and remediation in the platform.

## Why Event-Driven Here

Security analysis and policy response should not block request-response paths. Kafka lets the platform:

- decouple API processing from detection and remediation
- absorb traffic bursts with durable buffering
- replay events for incident analysis and model tuning
- scale consumers independently of API services

## Kafka Topics

- api-logs
- security-events
- threat-alerts
- audit-logs

## Topic Semantics

- `api-logs`: raw or normalized request context emitted by services and gateway-adjacent logic.
- `security-events`: curated security signals (auth failures, validation rejects, policy denies).
- `threat-alerts`: confirmed suspicious patterns from detection pipeline.
- `audit-logs`: immutable compliance-oriented traces.

## End-To-End Event Flow

1. A client request goes through ingress and API gateway.
2. `auth-service` and `user-service` process business/auth paths.
3. Services emit contextual records to `api-logs` (and optionally `security-events`).
4. `threat-detection-ai` consumes from Kafka, evaluates payloads, and classifies threats.
5. When a threat is detected, an alert is produced to `threat-alerts`.
6. `remediation-service` consumes alerts and applies response actions.
7. Important state transitions are written to `audit-logs`.

## Producer And Consumer Responsibilities

### Producers

- Keep event schema stable and backward compatible.
- Include minimal required context (service name, timestamp, request fingerprint, normalized payload).
- Avoid leaking secrets or raw credentials in events.

### Consumers

- Be idempotent (same event may be reprocessed after restart/rebalance).
- Commit offsets only after processing succeeds.
- Implement retry/backoff and dead-letter strategy for poison messages.

## Reliability Design

- Local mode uses single-node KRaft (`kafka:9092`) for developer velocity.
- Cloud environments should use highly available brokers and multi-AZ replication.
- Partitions should be sized by throughput and consumer parallelism requirements.
- Retention should support incident replay windows and compliance requirements.

## Ordering And Delivery Guarantees

- Kafka ordering is guaranteed per partition, not across topics.
- Critical causal chains should use deterministic keys (for example, request ID or session ID).
- At-least-once delivery is the baseline; consumers must tolerate duplicates.

## Security Considerations

- Enforce TLS/SASL in non-local environments.
- Restrict topic ACLs to least privilege.
- Do not publish sensitive PII unless encrypted/redacted.
- Monitor consumer lag to prevent silent blind spots in detection.

## Capacity And Sizing Guidance

- Start with throughput baselines per topic (events/sec, bytes/sec).
- Estimate retention storage as:
	- average event size x events/sec x retention seconds x replication factor
- Track p95 publish latency, consumer lag, rebalance frequency, and broker disk usage.

## Failure And Recovery Guidance

- Broker unavailable: buffer locally where possible, retry with jittered backoff.
- Consumer crash: restart from committed offset; verify lag catch-up.
- Poison messages: quarantine in dead-letter topic for forensic review.
- Data replay: re-run from historical offsets in controlled backfill jobs.

## Environment-Specific Notes

- Local: Docker Compose with KRaft and scripted topic creation.
- Dev/Prod (AWS/Azure): overlays should point to managed Kafka endpoints and secure auth.
- Do not ship local defaults (`kafka:9092`) to production.

## Flow Diagram

See: diagrams/kafka-event-flow.png
