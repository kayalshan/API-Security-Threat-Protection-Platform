# Deployment Architecture (AKS/EKS)

This document describes how the platform is deployed to Azure Kubernetes Service (AKS) and Amazon EKS.

## Deployment Layers

1. Base infrastructure (cluster, network, node pools)
2. Istio service mesh and ingress
3. Platform workloads (gateway, auth, user, detection, remediation)
4. Event backbone (Kafka and topics)
5. Observability and runbook-backed operations
6. Security controls and policy enforcement

## Kubernetes Layout

- Shared manifests: `k8s/base`
- Dev overlays:
	- `k8s/overlays/dev/aws`
	- `k8s/overlays/dev/azure`
- Prod overlays:
	- `k8s/overlays/prod/aws`
	- `k8s/overlays/prod/azure`

## Deployment Flow

1. Create namespace `api-security`.
2. Install and verify Istio control-plane and ingress gateway.
3. Apply overlay for target cloud and environment.
4. Verify rollout of each deployment.
5. Validate ingress routes and auth flow.
6. Confirm Kafka pipeline health (`api-logs` -> `threat-alerts`).

## AKS And EKS Differences

- Image registry paths differ (ACR vs ECR).
- Cloud metadata labels differ by overlay.
- Secret integration and identity binding differ by cloud provider.
- Ingress/public endpoint wiring differs based on cloud load balancer behavior.

## Pre-Production Checks

- Replica counts are appropriate for target environment.
- Secrets are sourced from managed secret stores (not placeholder literals).
- Kafka endpoints are production-grade, not local defaults.
- Alerting, dashboards, and incident runbooks are validated.

## Notes

Use the same deployment ordering and verification criteria in both AKS and EKS so incident response remains consistent across clouds.
