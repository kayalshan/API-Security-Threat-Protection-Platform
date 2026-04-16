# Runbooks

## Purpose

This directory contains operator-facing runbooks for the Unified API Security Threat Protection Platform. The goal is to make production support predictable: what to check first, how to narrow the blast radius, how to recover safely, and how to verify that protection controls are working again.

These documents are written against the repository state as it exists now. They are intended to be practical and honest about what is implemented in code and configuration today.

## Platform Scope

The platform combines:

- API Gateway routing on port `8080`
- Auth Service on port `8082`
- User Service on port `8081`
- Threat Detection AI service consuming Kafka events
- Remediation Service consuming threat alerts
- Istio ingress, routing, mTLS, and authorization controls
- Kafka topics supporting security detection and audit flows

## Runbook Set

- `incident-response.md`: incident command, initial triage, containment, recovery, and closure criteria
- `istio-troubleshooting.md`: ingress, sidecar, routing, mTLS, JWT, and authorization diagnostics
- `kafka-failure-recovery.md`: broker, topic, and consumer pipeline recovery
- `production-readiness-checklist.md`: pre-production controls, checks, and gaps to validate before release

## How To Use These Runbooks

1. Start with `incident-response.md` whenever the blast radius is not yet clear.
2. Switch to the component-specific runbook once the fault domain is known.
3. Record exact commands executed, timestamps, and recovery results while working.
4. Do not use destructive cleanup steps until logs and evidence have been collected.

## Repository-Specific Operating Assumptions

- Active deployment script namespace: `api-security`
- Istio ingress gateway resource: `api-security-gateway`
- API path routing is handled by API Gateway route definitions in:
  - `services/api-gateway/src/main/resources/application.yml` (host/local defaults)
  - `services/api-gateway/src/main/resources/application-docker.yml` (docker profile)
- `GatewayConfig.java` is used for CORS configuration, not route definitions
- Kafka topics expected by the application:
  - `api-logs`
  - `threat-alerts`
  - `security-events`
  - `audit-logs`

## Quick Path Sanity

Use these exact paths during incident triage and local verification:

- `GET /api/health`
- `POST /auth/login`
- `POST /auth/validate`
- `GET /users?email=<value>`

Avoid malformed paths such as `/users/api/health`; they are not valid routes in this platform.

## Before Calling This Production-Ready

Read `production-readiness-checklist.md` and validate each item for the target environment. The repository includes strong architectural intent, but several manifests and pipeline definitions are still placeholders. These runbooks are designed to support that reality rather than hide it.
