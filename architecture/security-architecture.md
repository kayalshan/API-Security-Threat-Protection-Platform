# Security Architecture

This document describes the platform security model, trust boundaries, and control implementation strategy.

## Security Objectives

- prevent common API attack paths (OWASP Top 10 class risks)
- enforce consistent identity and authorization across services
- detect suspicious behavior quickly and trigger response
- provide defensible auditability for operations and compliance

## Layered Security Model

## 1) Edge And Ingress Controls

- ingress gateway controls external entry points
- route-level policy limits exposed paths and methods
- optional WAF integration for pre-service filtering

## 2) Identity And Authentication

- `auth-service` handles login and token validation
- JWT is propagated through gateway and validated at service boundaries
- token verification failures are treated as security events

## 3) Service-To-Service Trust

- Istio mTLS enforces encrypted, authenticated east-west traffic
- AuthorizationPolicy narrows service communication paths
- RequestAuthentication applies identity-aware checks where required

## 4) Application-Layer Defenses

- input validation and sanitization at service entry points
- secure coding controls for SQLi/XSS resistance
- explicit handling for malformed or suspicious payloads

## 5) Event-Driven Detection

- services publish relevant events to Kafka topics (`api-logs`, `security-events`)
- `threat-detection-ai` analyzes patterns and emits `threat-alerts`
- remediation workflow consumes alerts and applies response actions

## 6) Monitoring, Audit, And Response

- logs, metrics, and traces support incident triage
- audit-friendly topics preserve security-relevant activity
- runbooks in `docs/runbooks` guide recovery steps

## Key Security Features

- Zero Trust (mTLS)
- JWT/OAuth2 Authentication
- Rate Limiting
- Input Validation
- WAF Integration
- AI-based Threat Detection

## Trust Boundaries

- External clients to ingress (untrusted boundary)
- Ingress/gateway to internal services (policy enforced boundary)
- Application services to Kafka (data integrity boundary)
- Detection to remediation actions (control boundary)

## Threat Coverage Mapping (High-Level)

- Broken authentication: JWT validation, auth flow monitoring
- Broken access control: mesh authz policy and route restrictions
- Injection risks: input validation and detection pipeline
- Security misconfiguration: versioned manifests, explicit policy files
- Insufficient logging: event topics and observability stack

## Deployment And Environment Guidance

- Namespace standard: `api-security`
- Local: pragmatic defaults for developer speed
- Dev/Prod: enforce stricter authn/authz, managed secrets, TLS everywhere
- Ensure overlays never retain local placeholders in production

## Secrets And Key Management

- avoid hardcoded secrets in manifests and docs
- use cloud-managed secret systems for AWS/Azure environments
- rotate JWT and integration secrets with defined cadence

## Security Validation Strategy

1. Unit and integration tests for auth and validation behavior.
2. E2E negative tests for SQLi/XSS payload handling.
3. Policy validation for Istio authn/authz manifests.
4. Runtime verification of detection pipeline and alert routing.

## Incident Readiness

- keep incident, Istio, and Kafka runbooks current with production behavior
- define severity thresholds and escalation paths
- rehearse rollback and containment procedures quarterly

## Recommended Next Hardening Steps

- enforce external secret integration in all cloud overlays
- add CI checks for security-manifest drift and risky policy changes
- validate rate limiting and abuse controls under load
- strengthen redaction of sensitive fields in logs/events

## Security Diagram

See: diagrams/high-level-architecture.png
