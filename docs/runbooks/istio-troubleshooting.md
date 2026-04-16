# Istio Troubleshooting Runbook

## Purpose

This runbook covers production troubleshooting for the Istio layer used by this platform: ingress, routing, sidecar injection, mTLS, JWT validation, and authorization policy behavior.

Use this document when traffic reaches the cluster but fails before, during, or immediately after service mesh handling.

## Managed Istio Resources in This Repository

- Gateway: `api-security-gateway`
- Virtual services:
	- `api-gateway-routing`
	- `auth-service`
	- `user-service`
- Destination rules:
	- `auth-service`
	- `user-service`
- Security resources:
	- `default` peer authentication with strict mTLS
	- `jwt-auth` request authentication
	- `api-security-policy` authorization policy
	- `api-gateway-cors` virtual service for CORS rules

Namespace expected by the active deployment script: `api-security`

## Symptoms and Likely Causes

### Symptom: all external requests fail

Likely causes:

- Istio ingress gateway service is unavailable
- Gateway resource is missing or rejected
- External IP or port changed
- Virtual service host or route rules no longer match incoming traffic

### Symptom: health works, protected routes fail

Likely causes:

- JWT request authentication misconfiguration
- Authorization policy mismatch
- API Gateway forwards traffic but downstream service rejects identity context

### Symptom: one service path fails, others work

Likely causes:

- Route for that path is missing or invalid
- Destination rule mismatch
- Service DNS or service port mismatch
- Sidecar not injected for the target workload

### Symptom: intermittent `503`, `502`, or upstream reset

Likely causes:

- Sidecar or pod restarts
- mTLS mismatch between workloads
- Service endpoints unavailable
- Outlier behavior caused by rapid rollout or unhealthy pods

## Fast Triage Commands

### Resource Inventory

```bash
kubectl get namespace api-security --show-labels
kubectl get gateway,virtualservice,destinationrule -n api-security
kubectl get peerauthentication,requestauthentication,authorizationpolicy -n api-security
kubectl get svc,pods,endpoints -n api-security
```

### Ingress Gateway Status

```bash
kubectl get svc -n istio-system istio-ingressgateway
kubectl get pods -n istio-system
kubectl logs -n istio-system deployment/istio-ingressgateway --tail=200
```

### Sidecar Injection Check

```bash
kubectl get namespace api-security --show-labels
kubectl get pods -n api-security -o jsonpath='{range .items[*]}{.metadata.name}{"  sidecars="}{.spec.containers[*].name}{"\n"}{end}'
```

The namespace should carry the label `istio-injection=enabled`. Each mesh-managed pod should include an `istio-proxy` container.

### Istio Proxy View

```bash
istioctl proxy-status
istioctl analyze -n api-security
```

## Standard Troubleshooting Flow

### 1. Confirm namespace and injection state

```bash
kubectl label namespace api-security istio-injection=enabled --overwrite
kubectl rollout restart deployment/api-gateway -n api-security
kubectl rollout restart deployment/auth-service -n api-security
kubectl rollout restart deployment/user-service -n api-security
```

Use this only if sidecars are missing. Restarting is required after changing namespace injection labels.

### 2. Confirm ingress reachability

```bash
export INGRESS_HOST=$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
export INGRESS_PORT=$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')

curl -i "http://${INGRESS_HOST}:${INGRESS_PORT}/api/health"
curl -i "http://${INGRESS_HOST}:${INGRESS_PORT}/users?email=test@example.com"
```

Interpretation:

- If both fail, focus on ingress gateway and gateway binding.
- If health succeeds but `/users` fails, focus on routing or security policy.
- If health and login succeed but `/users` fails with `401` or `403`, inspect JWT and auth policy.

### 3. Inspect gateway and route definitions

```bash
kubectl describe gateway api-security-gateway -n api-security
kubectl describe virtualservice api-gateway-routing -n api-security
kubectl describe virtualservice auth-service -n api-security
kubectl describe virtualservice user-service -n api-security
```

The route source of truth for API Gateway is YAML configuration:

- `services/api-gateway/src/main/resources/application.yml`
- `services/api-gateway/src/main/resources/application-docker.yml`

`GatewayConfig.java` is reserved for CORS behavior and should not be used as a second route source.

### 4. Inspect service endpoints

```bash
kubectl get endpoints api-gateway -n api-security
kubectl get endpoints auth-service -n api-security
kubectl get endpoints user-service -n api-security
```

If endpoints are empty, the problem is below Istio. Check deployment health, selectors, and container readiness.

### 5. Inspect security resources

```bash
kubectl describe peerauthentication default -n api-security
kubectl describe requestauthentication jwt-auth -n api-security
kubectl describe authorizationpolicy api-security-policy -n api-security
```

Repository-specific notes:

- Peer authentication is configured for strict mTLS.
- Request authentication currently targets workloads labeled `app: user-service`.
- Authorization policy allows traffic from any authenticated request principal.

If policy behavior changed after a config edit, reapply the intended manifests from the repo before deeper changes.

## Common Failure Patterns

### Missing or broken sidecars

Signals:

- No `istio-proxy` container in affected pods
- `istioctl proxy-status` shows missing proxies
- Traffic bypasses or never enters the mesh as expected

Actions:

1. Confirm `istio-injection=enabled` on the namespace.
2. Restart affected deployments.
3. Recheck containers and proxy sync state.

### mTLS failures

Signals:

- Upstream connect errors
- `503` after policy changes
- Envoy logs referencing TLS handshake issues

Actions:

```bash
kubectl logs deployment/api-gateway -n api-security -c istio-proxy --tail=200
kubectl logs deployment/user-service -n api-security -c istio-proxy --tail=200
kubectl apply -f istio/security/mtls-strict.yaml -n api-security
kubectl apply -f istio/destination-rules/ -n api-security
```

Validate that destination rules and service expectations still align with strict mTLS.

### JWT or authorization failures

Signals:

- Requests to protected routes return `401` or `403`
- Health endpoints remain reachable
- Login may still work because it is public

Actions:

```bash
kubectl apply -f istio/security/request-authentication.yaml -n api-security
kubectl apply -f istio/security/authorization-policy.yaml -n api-security
kubectl logs deployment/api-gateway -n api-security --tail=200
kubectl logs deployment/user-service -n api-security --tail=200
```

Then test with and without a Bearer token to confirm expected policy behavior.

### Route mismatch after config change

Signals:

- Only one URI prefix fails
- Virtual service shows unexpected match order or missing match blocks

Actions:

```bash
kubectl apply -f istio/gateways/ -n api-security
kubectl apply -f istio/virtual-services/ -n api-security
```

If the route remains broken, compare the active resource YAML with the repository manifests before editing live objects manually.

## Recovery Steps

### Safe Reapply Sequence

Use this order to minimize reference errors:

```bash
kubectl apply -f istio/gateways/ -n api-security
kubectl apply -f istio/virtual-services/ -n api-security
kubectl apply -f istio/destination-rules/ -n api-security
kubectl apply -f istio/security/mtls-strict.yaml -n api-security
kubectl apply -f istio/security/request-authentication.yaml -n api-security
kubectl apply -f istio/security/authorization-policy.yaml -n api-security
```

### Full Platform Reconciliation

```bash
./scripts/deploy-all.sh k8s dev
./scripts/deploy-all.sh k8s prod
```

Use only the relevant environment. This is appropriate when multiple mesh resources drifted or partial apply operations left the cluster inconsistent.

## Validation After Recovery

Validate all of the following:

1. Ingress gateway has healthy pods and a reachable external address.
2. `GET /api/health` succeeds through the ingress.
3. `POST /auth/login` succeeds.
4. `GET /users` succeeds with a valid Bearer token.
5. `istioctl proxy-status` shows synchronized proxies.
6. No relevant `istio-proxy` logs show handshake or route resolution errors.
7. Route tests use valid paths only (`/api/health`, `/auth/**`, `/users?email=...`) and not malformed paths such as `/users/api/health`.

## Escalate When

- Istio control plane itself is unhealthy
- Gateway service has no external address in a production environment that requires one
- Multiple services fail after policy reapply with no clear application-side error
- You suspect a service-to-service trust or certificate issue outside the repo-managed configuration
