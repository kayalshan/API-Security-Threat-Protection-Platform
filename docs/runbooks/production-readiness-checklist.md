# Production Readiness Checklist

## Purpose

Use this checklist before promoting the platform into a production environment or before declaring an existing environment production-ready. The repository shows the intended architecture clearly, but readiness depends on verified implementation details, not design intent alone.

## Release Gate

The environment is not production-ready until every critical item below is either complete or explicitly risk-accepted.

## Architecture and Environment

- Confirm the target namespace, ingress hostname, TLS strategy, and external DNS records.
- Confirm whether the environment is local demo, shared non-production, or real production.
- Confirm that the deployed manifests in the target cluster match the repository version being released.
- Confirm that rollback instructions are tested for the exact release mechanism in use.

## Application Readiness

- `POST /auth/login` works end to end.
- `POST /auth/validate` behaves as expected for valid and invalid tokens.
- `GET /users?email=<value>` behaves as intended for the target profile:
	- demo/local profile may allow public access
	- hardened production profile should require authentication and reject unauthenticated requests
- `GET /api/health` succeeds through the real ingress path.
- Threat Detection AI service health endpoint is reachable and monitored.
- Remediation Service health endpoint is reachable and monitored.

## Security Controls

- JWT issuance and validation are tested with real environment keys or JWKS.
- Istio `RequestAuthentication` values are correct for the production issuer.
- Authorization policy behavior is validated with positive and negative test cases.
- mTLS is enabled and tested for service-to-service traffic.
- Rate limiting and abuse controls are configured for real traffic patterns.
- Input validation and OWASP protections are enabled in the application path actually serving traffic.
- Secrets are managed outside source control and rotated through an approved process.

## Kafka and Event Pipeline

- Kafka is deployed with a production topology, not a single-node demo broker.
- Replication factor and storage durability meet recovery objectives.
- Required topics exist with approved partition and retention settings.
- Producers and consumers are tested with real message flow.
- Consumer lag is observable and alertable.
- A replay and backfill strategy exists for dropped or delayed security events.

## Observability

- Centralized logs are enabled for all services and ingress components.
- Metrics exist for request volume, error rate, latency, pod health, and Kafka health.
- Alerting thresholds are defined for ingress failure, auth failure, service unavailability, and pipeline disruption.
- Dashboards exist for platform health and incident triage.
- Time synchronization and timestamp consistency are verified across components.

## Operational Safety

- On-call ownership is defined.
- Incident severity definitions are agreed and published.
- Runbooks are available to operators with cluster access.
- Destructive procedures require explicit approval and are logged.
- Backup and recovery procedures exist for stateful dependencies.
- Deployment and cleanup scripts are reviewed for environment-specific safety.

## Repository Gaps To Verify Explicitly

At the time of writing, verify these items carefully before calling the platform production-ready:

- Several Kubernetes base manifests in `k8s/base` are empty placeholders.
- Observability configuration files such as Prometheus and Logstash configs are empty placeholders.
- GitHub Actions workflow files in `ci-cd/github-actions` are empty placeholders.
- Verify all automation for deploy, cleanup, and rollback targets namespace `api-security` (or an explicitly approved override).
- The included Kafka topology is single-node KRaft and is suitable for local or demo use, not production as-is.

## Sign-Off Questions

Answer each question explicitly:

1. Can the team detect a failed login path, failed `/users` path, failed ingress path, and failed Kafka pipeline within minutes?
2. Can the team recover the platform without improvising commands during an incident?
3. Are security controls validated against the real production identity provider and network path?
4. Is there a tested rollback for both application changes and configuration changes?
5. Has someone verified that the cluster resources and CI/CD pipeline are not still placeholders?

If any answer is no, the environment is not yet production-ready.