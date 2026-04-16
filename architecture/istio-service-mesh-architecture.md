# Istio Service Mesh Architecture

This document describes how Istio is used to secure and control service-to-service traffic for the platform.

## Design Goals

- enforce zero-trust communication between workloads
- separate traffic policy from application code
- provide consistent telemetry for debugging and incident response
- support safe rollout and rollback patterns

## Features

- mTLS
- Traffic Routing
- Policy Enforcement
- Observability

## Mesh Topology

- Namespace: `api-security`
- Entry point: Istio ingress gateway
- In-mesh workloads: `api-gateway`, `auth-service`, `user-service`, optional downstream services
- Sidecars: Envoy proxies attached per workload (injection enabled)

## Traffic Flow

1. External traffic reaches Istio ingress gateway.
2. Gateway routes to `api-gateway` via VirtualService rules.
3. `api-gateway` forwards to backend services.
4. East-west traffic is mediated by sidecars with mTLS and policy checks.
5. Response flows back through mesh path with telemetry emitted at each hop.

## Routing Model

- Gateway resource defines host/port exposure.
- VirtualServices define path-based routing (`/auth/**`, `/users/**`, health paths).
- DestinationRules define service traffic policy and mTLS settings.
- AuthorizationPolicy and RequestAuthentication enforce identity-aware access.

## Security Policy Layers

### PeerAuthentication

- Use STRICT mTLS in non-local environments.
- Prevent plaintext pod-to-pod traffic.

### RequestAuthentication

- Validate JWT at mesh boundary where applicable.
- Keep issuer/JWKS config aligned with auth implementation.

### AuthorizationPolicy

- Deny by default where practical.
- Allow only required principals, paths, and methods.

## Resilience Controls

- Retries for transient backend failures.
- Timeouts to avoid request pile-up.
- Circuit breaking via DestinationRules for unstable dependencies.
- Optional outlier detection for bad endpoint eviction.

## Observability And Debugging

- Use Istio metrics to track request rate, error rate, and latency by service/path.
- Correlate ingress logs with app logs and Kafka event IDs when tracing incidents.
- Use `istioctl proxy-status` and `istioctl analyze` during rollout diagnostics.

## Deployment Guidance

1. Install/verify Istio control plane.
2. Label namespace for sidecar injection.
3. Apply Gateway, then VirtualServices, then DestinationRules.
4. Apply security policies (PeerAuthentication, RequestAuthentication, AuthorizationPolicy).
5. Validate route reachability and policy behavior.

## Common Misconfigurations To Avoid

- VirtualService host mismatch with service DNS name.
- Policy scoped to wrong namespace.
- STRICT mTLS enabled before all workloads have sidecars.
- Health paths unintentionally blocked by authz rules.

## Production Hardening Checklist

- TLS termination and hostnames are explicit and tested.
- JWT auth rules are validated against real issuer/JWKS.
- Deny and allow rules are reviewed per service boundary.
- Canary rollout and rollback plans are documented and rehearsed.

## Diagram

See: diagrams/istio-traffic-flow.png
