# Threat Model

This threat model captures likely abuse paths for the current platform architecture and maps each one to existing controls and follow-up actions.

## Scope

- Ingress and gateway routing
- Auth and user services
- Kafka security event pipeline
- Threat detection and remediation loop
- Kubernetes/Istio runtime controls

## Threat Categories (STRIDE-Oriented)

## Spoofing

- Risk: forged JWT or stolen token replay.
- Current controls: token validation endpoint, auth checks, gateway enforcement.
- Gaps to monitor: token lifetime tuning, stronger secret rotation process.

## Tampering

- Risk: manipulated request payloads and event poisoning.
- Current controls: payload handling patterns, security logging, downstream detection.
- Gaps to monitor: stricter schema validation for events.

## Repudiation

- Risk: inability to prove who triggered sensitive actions.
- Current controls: API and Kafka event trails, observability stack.
- Gaps to monitor: immutable audit retention policy.

## Information Disclosure

- Risk: sensitive values leaking in logs or error messages.
- Current controls: runbook guidance and controlled exposure of endpoints.
- Gaps to monitor: log redaction enforcement and periodic log review.

## Denial Of Service

- Risk: request floods or broker saturation.
- Current controls: gateway and mesh policy points, horizontal scaling model.
- Gaps to monitor: explicit rate-limit policy rollout and load-test thresholds.

## Elevation Of Privilege

- Risk: bypass of route or service authorization boundaries.
- Current controls: Istio authorization policy, mTLS, service isolation.
- Gaps to monitor: policy drift detection and CI validation for security manifests.

## Priority Threat Scenarios

1. SQL injection payloads propagated through user endpoints.
2. XSS-style payloads captured in event stream and not blocked quickly.
3. Auth path abuse (credential stuffing or token replay).
4. Kafka outage causing blind spots in threat detection.

## Mitigation Priorities

1. Keep E2E security payload checks in CI for every environment.
2. Enforce namespace and overlay consistency (`api-security`, cloud-specific overlays).
3. Validate Kafka topic readiness and consumer lag alerting.
4. Maintain tested incident runbooks for ingress, auth, and Kafka failures.
