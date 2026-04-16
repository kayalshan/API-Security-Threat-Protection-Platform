# Data Flow Diagram (Narrative)

This document describes the main data flows so threat modeling can stay aligned with runtime behavior.

## Primary Request Flow

1. Client sends request to ingress endpoint.
2. Istio ingress routes traffic to `api-gateway`.
3. Gateway forwards to `auth-service` or `user-service`.
4. Service response returns through gateway to client.

## Security Event Flow

1. Service emits security-relevant log/event to Kafka topic `api-logs`.
2. `threat-detection-ai` consumes `api-logs` and evaluates content.
3. When a threat is detected, the service publishes to `threat-alerts`.
4. `remediation-service` consumes alerts and applies mitigation actions.

## Trust Boundaries

- External boundary: public client to ingress.
- Mesh boundary: ingress to in-cluster services (mTLS/policy enforced).
- Data boundary: services writing to and reading from Kafka.
- Control boundary: remediation actions affecting policy/WAF behavior.

## Security-Relevant Assets

- JWT tokens and auth validation paths.
- API request payloads and derived security events.
- Kafka topics: `api-logs`, `security-events`, `threat-alerts`, `audit-logs`.
- Service configuration and secrets.

## Suggested Diagram Blocks

- Client
- Istio Ingress Gateway
- API Gateway
- Auth Service
- User Service
- Kafka
- Threat Detection AI
- Remediation Service
- Observability Stack
