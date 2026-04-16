# A6 – Security Misconfiguration

## Overview

Security misconfiguration is the most common OWASP finding. It results from insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, verbose error messages, unnecessary features, or unpatched systems. In a microservices platform like this one, misconfiguration can occur at every layer: application, container, Kubernetes, Istio, Kafka, and observability infrastructure.

**OWASP Reference:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## Common Misconfiguration Areas
```text
| Layer | Misconfiguration Risk | Platform Component |
|-------|--------------------|-------------------|
| Application | Debug mode in production, default credentials | `application-prod.yml`, Spring Boot Actuator |
| Container | Running as root, privileged mode, no read-only FS | `Dockerfile`, `k8s/base/` deployments |
| Kubernetes | No resource limits, privileged pods, public NodePorts | All YAML manifests in `k8s/base/` |
| Istio | mTLS in PERMISSIVE mode, missing AuthorizationPolicy | `istio/security/` |
| Kafka | No authentication, world-readable topics | `messaging/kafka/server.properties` |
| Observability | Kibana/Grafana exposed without auth | `observability/` stack |
| HTTP Headers | Missing security headers (CSP, HSTS, etc.) | API Gateway responses |
| Error handling | Stack traces returned to users | All Spring Boot services |
```
---

## Prevention Controls

### 1. Spring Boot — Harden Actuator Endpoints

Actuator endpoints expose heap dumps, thread state, environment variables, and configuration. Never expose them publicly.

```yaml
# services/*/application-prod.yml — production hardening
management:
  endpoints:
    web:
      exposure:
        include: health, info     # expose ONLY health and info
        # Do NOT include: env, beans, mappings, heapdump, threaddump, metrics
  endpoint:
    health:
      show-details: never         # do not reveal DB status, disk, etc. to unauthenticated users
  server:
    port: 8081                    # actuator on a separate, non-public port
```

Restrict Actuator access to the Kubernetes liveness/readiness probes and internal monitoring only:

```yaml
# istio/security/authorization-policy.yaml — block external actuator access
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-actuator-external
  namespace: api-security
spec:
  action: DENY
  rules:
    - to:
        - operation:
            paths: ["/actuator/**"]
      from:
        - source:
            notPrincipals: ["cluster.local/ns/kube-system/sa/prometheus-scraper"]
```

### 2. Disable Debug Mode in Production

```yaml
# services/*/application-prod.yml
spring:
  jpa:
    show-sql: false               # never log SQL in production
  thymeleaf:
    cache: true                   # enable template caching
logging:
  level:
    root: WARN
    com.unified: INFO
    org.springframework.security: WARN   # Avoid auth debug logs leaking tokens
```

Ensure `SPRING_PROFILES_ACTIVE=prod` is set in Kubernetes deployments:

```yaml
# k8s/base/auth-service-deployment.yaml
env:
  - name: SPRING_PROFILES_ACTIVE
    value: "prod"
```

### 3. Docker — Least-Privilege Container Configuration

```dockerfile
# services/api-gateway/Dockerfile — hardened example
FROM eclipse-temurin:21-jre-alpine AS runtime

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --chown=appuser:appgroup target/*.jar app.jar

# Drop all capabilities
USER appuser

# Expose only the application port
EXPOSE 8080

# Use exec form to ensure proper signal handling
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 4. Kubernetes — Pod Security Standards

Apply Pod-level security constraints across all deployments:

```yaml
# k8s/base/api-gateway-deployment.yaml — security context
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api-gateway
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "100m"
              memory: "256Mi"
          volumeMounts:
            - name: tmp
              mountPath: /tmp     # allow writes only to /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

Apply the `restricted` Pod Security Standard to the namespace:

```yaml
# k8s/base/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: api-security
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 5. Istio — Enforce mTLS STRICT Mode

Ensure no service accepts plaintext traffic. The default should be STRICT, not PERMISSIVE:

```yaml
# istio/security/mtls-strict.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: api-security
spec:
  mtls:
    mode: STRICT    # reject all non-mTLS traffic
```

Verify the current state:

```bash
kubectl get peerauthentication -n api-security -o yaml | grep mode
# Expected output: mode: STRICT
```

### 6. Kafka — Authentication and Authorization

The `messaging/kafka/server.properties` must enable SASL authentication and ACL-based authorization:

```properties
# messaging/kafka/server.properties — hardened
listeners=SASL_SSL://0.0.0.0:9093
advertised.listeners=SASL_SSL://kafka:9093
security.inter.broker.protocol=SASL_SSL
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
sasl.enabled.mechanisms=SCRAM-SHA-512

# Authorization — enable ACLs
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
allow.everyone.if.no.acl.found=false   # default-deny
super.users=User:kafka-admin

# Disable auto topic creation
auto.create.topics.enable=false
```

### 7. HTTP Security Headers

Apply security headers to all API responses at the API Gateway:

```java
// API Gateway — WebSecurityConfig or filter
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .headers(headers -> headers
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000)
                .preload(true))
            .contentTypeOptions(Customizer.withDefaults())
            .frameOptions(frame -> frame.deny())
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("default-src 'none'; script-src 'self'; " +
                                  "connect-src 'self'; img-src 'self'; style-src 'self'"))
            .referrerPolicy(rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            .permissionsPolicy(pp -> pp.policy("geolocation=(), microphone=(), camera=()"))
        )
        .build();
}
```

### 8. Disable Unused Features and Endpoints

```yaml
# application-prod.yml — disable Spring Boot features not needed in production
spring:
  devtools:
    restart:
      enabled: false
  h2:
    console:
      enabled: false    # never expose H2 console even if H2 is on the classpath
```

### 9. CI/CD — Infrastructure-as-Code Security Scanning

Add Checkov to the CI pipeline to scan Kubernetes and Terraform manifests:

```yaml
# ci-cd/github-actions/security-scan.yml — additional step
- name: Scan IaC with Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    directory: k8s/
    framework: kubernetes
    soft_fail: false

- name: Scan Terraform with Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    directory: terraform/
    framework: terraform
    soft_fail: false
```

---

## Configuration Checklist

- [ ] `SPRING_PROFILES_ACTIVE=prod` set in all Kubernetes deployments
- [ ] Actuator endpoints restricted to `health` and `info` only, on a non-public port
- [ ] `show-sql: false` in production Spring profiles
- [ ] All containers run as non-root with `readOnlyRootFilesystem: true`
- [ ] Kubernetes namespace has `pod-security.kubernetes.io/enforce: restricted`
- [ ] Resource limits (CPU and memory) set on every container
- [ ] Istio mTLS mode = `STRICT` across the namespace
- [ ] Kafka listeners use `SASL_SSL` only; `allow.everyone.if.no.acl.found=false`
- [ ] All HTTP responses include HSTS, CSP, X-Content-Type-Options headers
- [ ] H2 console and Spring DevTools disabled in production profile
- [ ] Checkov or equivalent IaC scanning in CI pipeline
- [ ] No default or blank passwords in any configuration file

---

## Testing

| Test Type | Tool | Coverage |
|-----------|------|----------|
| IaC Scan | Checkov | K8s, Terraform misconfigurations |
| Container Scan | Trivy (`docker scan`) | Base image vulnerabilities, misconfig |
| DAST | OWASP ZAP | HTTP header checks, directory enumeration |
| Compliance | kube-bench | Kubernetes CIS benchmark |
| Manual | Postman | Verify Actuator endpoints inaccessible |

---

## Platform Files

| File | Purpose |
|------|---------|
| `services/auth-service/application-prod.yml` | Production-specific Spring Boot config |
| `k8s/base/namespace.yaml` | Namespace Pod Security Standard labels |
| `k8s/base/api-gateway-deployment.yaml` | Container security context |
| `istio/security/mtls-strict.yaml` | Enforce mTLS |
| `messaging/kafka/server.properties` | Kafka security settings |
| `ci-cd/github-actions/security-scan.yml` | CI security scan pipeline |

---

## References

- [OWASP Security Misconfiguration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
