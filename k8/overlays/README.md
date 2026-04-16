# Kubernetes Environment Layout

This directory now separates Kubernetes configuration by operating model instead of using a single shared placeholder overlay.

## Layout

- `k8s/base`: shared service, deployment, and namespace definitions
- `k8s/overlays/local`: local Kubernetes setup using the Spring Cloud Config Server pattern
- `k8s/overlays/dev/aws`: dev profile for AWS EKS-style deployments
- `k8s/overlays/dev/azure`: dev profile for Azure AKS-style deployments
- `k8s/overlays/prod/aws`: prod profile for AWS EKS-style deployments
- `k8s/overlays/prod/azure`: prod profile for Azure AKS-style deployments

## Intended Usage

### Local Spring Cloud style setup

Use this when you want the Spring services to boot with the `dev` profile and resolve configuration from a local Spring Cloud Config Server inside the cluster.

```bash
kubectl apply -k k8s/overlays/local -n api-security
```

### Dev on AWS or Azure

```bash
kubectl apply -k k8s/overlays/dev/aws -n api-security
kubectl apply -k k8s/overlays/dev/azure -n api-security
```

### Production on AWS or Azure

```bash
kubectl apply -k k8s/overlays/prod/aws -n api-security
kubectl apply -k k8s/overlays/prod/azure -n api-security
```

## What Changes Between Environments

- Spring profile selection
- whether Spring Cloud Config Server is used
- image registry naming for AWS ECR or Azure Container Registry
- replica counts for dev versus prod
- cloud metadata labels carried by the workloads

## Required Follow-Up Before Real Production Use

- Replace placeholder image registry names in cloud overlays
- Replace generated secret placeholders with external secret integration
- Provide a production Kafka bootstrap endpoint instead of the local `kafka:9092` default
- Align the remediation service container with a real HTTP health endpoint if it must be mesh-routed and probed
