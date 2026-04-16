# Architecture Documentation

This document explains how the platform is put together and how traffic, security controls, and events move through the system.

## System Goals

- Protect APIs against OWASP-style attacks without adding brittle point solutions.
- Keep runtime security controls consistent across services.
- Detect suspicious behavior in near real time and trigger remediation.
- Provide enough observability for fast triage and incident response.

## Core Runtime Components

- Istio ingress and service mesh for traffic control and mTLS.
- API Gateway for route orchestration and auth-aware request flow.
- Spring Boot microservices (`auth-service`, `user-service`, `api-gateway`).
- Kafka for asynchronous security/event pipelines.
- Python `threat-detection-ai` service for event analysis.
- `remediation-service` for downstream response actions.

## Request And Event Flow

1. A client request enters through Istio ingress.
2. The request is routed to `api-gateway`.
3. Gateway forwards traffic to `auth-service` or `user-service` based on route.
4. Business services publish security-relevant events to Kafka topics.
5. `threat-detection-ai` consumes events, detects suspicious patterns, and publishes alerts.
6. `remediation-service` consumes alerts for policy or enforcement actions.

## Security Controls By Layer

- Edge and mesh: ingress policy, mTLS, authorization policy.
- Gateway: auth flow and route-level enforcement.
- Service layer: input handling and safe processing patterns.
- Event layer: immutable event trail for detection and auditing.

## Deployment Model

- Base Kubernetes manifests are under `k8s/base`.
- Environment overlays are under:
	- `k8s/overlays/local`
	- `k8s/overlays/dev/aws`
	- `k8s/overlays/dev/azure`
	- `k8s/overlays/prod/aws`
	- `k8s/overlays/prod/azure`

## Operational Notes

- Namespace convention is `api-security`.
- Local-first testing is done with Docker Compose plus E2E scripts in `tests/e2e`.
- Runbooks are maintained in `docs/runbooks` and should be used during live incidents.