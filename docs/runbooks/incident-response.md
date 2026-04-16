# Incident Response Runbook

## Purpose

This runbook describes how to respond to production incidents affecting the Unified API Security Threat Protection Platform. It is written for operators responsible for the API Gateway, Auth Service, User Service, Kafka event flow, Threat Detection AI, Remediation Service, and the Istio-based ingress path.

Use this document for live incidents. Use the more specialized runbooks for deep recovery work:

- `docs/runbooks/istio-troubleshooting.md` for ingress, routing, mTLS, and JWT policy issues
- `docs/runbooks/kafka-failure-recovery.md` for broker, topic, and consumer pipeline failures
- `docs/runbooks/production-readiness-checklist.md` for pre-release validation and operational controls

## System Snapshot

- Primary namespace: `api-security`
- Local entrypoint: `http://localhost:8080`
- Kubernetes ingress entrypoint: Istio Ingress Gateway on port `80`
- Public API paths used operationally:
	- `POST /auth/login`
	- `POST /auth/validate`
	- `GET /users?email=<value>`
	- `GET /api/health`
	- invalid path example to avoid: `GET /users/api/health`
- Kafka topics in active use:
	- `api-logs`
	- `threat-alerts`
	- `security-events`
	- `audit-logs`

## Severity Model

### Sev 1

- External traffic cannot reach the platform
- Authentication is fully unavailable
- Istio ingress failure blocks all production requests
- Kafka outage prevents threat detection and remediation during an active attack
- Widespread security control bypass is confirmed or highly likely

### Sev 2

- One core service is unavailable or degraded
- Threat alerts are delayed or not reaching remediation
- Elevated error rates or latency affect user-facing paths
- JWT validation or authorization policy fails for a subset of traffic

### Sev 3

- Non-critical operational issue with a workaround
- Observability or reporting degradation without immediate customer impact
- Single node or pod instability with healthy service failover

## Roles During an Incident

- Incident commander: owns coordination, scope, timeline, and next actions
- Communications lead: updates stakeholders and tracks customer impact
- Service owner: executes diagnosis and remediation on the affected component
- Security lead: determines if the event is malicious or accidental and whether containment is required

If staffing is limited, combine roles, but keep one person explicitly accountable for command and communication.

## Trigger Conditions

Start this runbook when any of the following occurs:

- Health checks fail at the ingress or API gateway layer
- Login requests fail or return sustained `401`, `403`, `429`, or `5xx` responses
- `GET /users` latency spikes or returns repeated `5xx`
- Kafka consumers stop processing `api-logs` or `threat-alerts`
- Threat Detection AI or Remediation Service stops receiving expected work
- Suspected OWASP-style attack reaches application services despite gateway and mesh protections

## Immediate Response Checklist

Complete these steps in order during the first 15 minutes.

1. Declare the incident, assign severity, and name an incident commander.
2. Capture the start time, detection source, and affected user path.
3. Confirm whether the problem is local, service-specific, namespace-wide, or platform-wide.
4. Freeze non-essential production changes until stabilization.
5. Verify core service reachability.
6. Identify whether the issue is ingress, application, or Kafka pipeline related.
7. Decide whether containment is required before full diagnosis.

## First-Line Diagnostics

### Kubernetes Health

```bash
kubectl get pods -n api-security
kubectl get svc -n api-security
kubectl get gateway,virtualservice,destinationrule -n api-security
kubectl get peerauthentication,requestauthentication,authorizationpolicy -n api-security
```

### Rollout and Restart Signals

```bash
kubectl rollout status deployment/api-gateway -n api-security --timeout=120s
kubectl rollout status deployment/auth-service -n api-security --timeout=120s
kubectl rollout status deployment/user-service -n api-security --timeout=120s
kubectl rollout status deployment/threat-detection-ai -n api-security --timeout=120s
kubectl rollout status deployment/remediation-service -n api-security --timeout=120s
```

### Pod Logs

```bash
kubectl logs deployment/api-gateway -n api-security --tail=200
kubectl logs deployment/auth-service -n api-security --tail=200
kubectl logs deployment/user-service -n api-security --tail=200
kubectl logs deployment/threat-detection-ai -n api-security --tail=200
kubectl logs deployment/remediation-service -n api-security --tail=200
```

### Ingress Validation

```bash
export INGRESS_HOST=$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
export INGRESS_PORT=$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')

curl -i "http://${INGRESS_HOST}:${INGRESS_PORT}/api/health"
curl -i -H 'Content-Type: application/json' \
	-d '{"username":"admin","password":"password"}' \
	"http://${INGRESS_HOST}:${INGRESS_PORT}/auth/login"
```

### Local Recovery Reference

If the incident is in a local or demo environment rather than Kubernetes:

```bash
docker compose ps
docker compose logs --tail=200 api-gateway auth-service user-service threat-detection-ai remediation-service kafka
curl -i http://localhost:8080/api/health
```

## Decision Tree

### If all requests fail at the edge

- Check Istio ingress service status and external IP assignment
- Check the `api-security-gateway` gateway object and the `api-gateway-routing` virtual service
- Confirm the API Gateway container or pod is healthy
- If the failure began after a mesh or ingress change, roll back the most recent change first

### If login fails but health succeeds

- Inspect Auth Service logs first
- Verify `/auth/login` routing still points to `api-gateway`
- Check JWT-related config and request authentication policy if only authenticated routes fail
- Determine whether the issue is bad credentials handling, token creation, or gateway validation

### If `/users` fails but login succeeds

- Inspect User Service logs and recent deployment state
- Confirm Kafka availability if the request path now blocks on event publication
- Validate the `GET /users` path through the gateway and service mesh

### If alerts are not reaching remediation

- Check Kafka broker health and topic availability
- Verify Threat Detection AI consumer lag or crashes
- Verify Remediation Service consumer logs
- Switch to the Kafka recovery runbook if the issue is message flow related

## Containment Guidance

Use containment only when it reduces active harm faster than it increases customer impact.

### Security Event Containment

- Tighten ingress exposure using Istio policies if active malicious traffic is confirmed
- Rate limit or block abusive sources at the earliest layer available
- Prefer targeted controls over full service shutdown when possible
- Preserve logs before destructive cleanup or pod recycling

### Platform Stability Containment

- Stop recent rollouts that correlate with the incident
- Scale down only the clearly faulty workload if it is poisoning downstream systems
- Avoid restarting Kafka first unless broker instability is proven

## Service Restoration Steps

### Restart a Single Deployment

```bash
kubectl rollout restart deployment/api-gateway -n api-security
kubectl rollout restart deployment/auth-service -n api-security
kubectl rollout restart deployment/user-service -n api-security
kubectl rollout restart deployment/threat-detection-ai -n api-security
kubectl rollout restart deployment/remediation-service -n api-security
```

Run only the command for the affected service, then verify health before touching another component.

### Reapply Istio Resources

```bash
kubectl apply -f istio/gateways/ -n api-security
kubectl apply -f istio/virtual-services/ -n api-security
kubectl apply -f istio/destination-rules/ -n api-security
kubectl apply -f istio/security/mtls-strict.yaml -n api-security
kubectl apply -f istio/security/request-authentication.yaml -n api-security
kubectl apply -f istio/security/authorization-policy.yaml -n api-security
```

### Re-run the Platform Deployment

```bash
./scripts/deploy-all.sh k8s dev
./scripts/deploy-all.sh k8s prod
```

Use the correct overlay for the affected environment. Re-deploy only after capturing logs and confirming the failure is configuration or rollout related.

## Validation Before Closing the Incident

Confirm each item below:

1. `GET /api/health` returns `200` through the intended ingress path.
2. `POST /auth/login` succeeds for a known test credential.
3. `GET /users?email=<value>` works through gateway using the expected profile policy.
4. Kafka topics exist and consumers resume normal processing.
5. Threat alerts can flow from detection to remediation.
6. No unexpected restart loops remain in `api-security`.
7. Logs and relevant timestamps are preserved for review.

## Escalation Rules

Escalate to security leadership immediately if any of the following is true:

- There is evidence of credential abuse, token forgery, or access control bypass
- Sensitive data may have been exposed
- Threat Detection AI or remediation logic was bypassed during an active attack
- The blast radius includes multiple services or multiple environments

Escalate to platform engineering if any of the following is true:

- Istio control plane or ingress gateway is unstable
- Kubernetes scheduling, networking, or DNS issues are involved
- Recovery requires namespace-wide restarts, reconfiguration, or rollback

## Communication Template

Use a short, factual update format:

```text
Incident: <short title>
Severity: <Sev 1 | Sev 2 | Sev 3>
Start time: <UTC timestamp>
Impact: <who or what is affected>
Current status: <investigating | mitigating | monitoring | resolved>
Current hypothesis: <best current explanation>
Next action: <single highest-value step>
Next update: <time>
```

## Post-Incident Review Requirements

Complete a review within two business days for Sev 1 and Sev 2 incidents.

Capture at minimum:

- Timeline from detection to recovery
- Root cause and contributing factors
- Why existing controls did or did not detect the issue earlier
- What manual recovery steps should become automated
- What monitoring, alerting, testing, or runbook changes are required

## Namespace Safety Note

The deployment and cleanup scripts are aligned to namespace `api-security`. Keep this value consistent when running destructive operations in shared or production-like environments.
