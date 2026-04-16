# A3 – Sensitive Data Exposure

## Overview

Sensitive Data Exposure occurs when applications do not adequately protect sensitive information such as financial data, healthcare records, passwords, API keys, or PII. Attackers can steal or modify weakly protected data to conduct fraud, identity theft, or other crimes. This is often caused by missing encryption, weak cryptographic algorithms, or secrets leaking through logs and error messages.

In this platform, sensitive data flows through the API Gateway, Auth-Service, User-Service, Kafka event streams, and observability pipelines. Each of these channels must apply encryption and data minimization.

**OWASP Reference:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

## Data Classification

```text
| Data Type | Classification | Examples in Platform |
|-----------|---------------|----------------------|
| Authentication credentials | Critical | Passwords, JWT secrets, API keys |
| PII | Confidential | Usernames, email addresses, IP addresses |
| Security events | Confidential | Threat detection logs, incident details |
| Service configuration | Confidential | DB connection strings, Kafka credentials |
| General payload data | Internal | Request metadata, timestamps |
```
---

## Attack Vectors
```text
| Vector | Description | Platform Exposure |
|--------|-------------|-------------------|
| Unencrypted data at rest | DB or message store lacks encryption | MySQL, Kafka topic data |
| Unencrypted data in transit | Missing TLS between services | Istio gateways, Kafka producers |
| Secrets in source code / config | Hardcoded credentials in `application.yml` | Auth-Service JWT secret |
| Sensitive data in logs | PII written to ELK stack without masking | Logstash pipelines |
| Sensitive data in error responses | Stack traces or DB errors returned to clients | API Gateway error handlers |
| Weak or outdated cryptography | MD5/SHA1 password hashing | Auth-Service password storage |
```
---

## Prevention Controls

### 1. Encrypt Data in Transit — TLS Everywhere

All external traffic must terminate at the Istio Ingress Gateway with TLS 1.2+ enforced:

```yaml
# istio/gateways/api-ingress-gateway.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: api-ingress-gateway
  namespace: api-security
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 443
        name: https
        protocol: HTTPS
      tls:
        mode: SIMPLE
        credentialName: platform-tls-cert
        minProtocolVersion: TLSV1_2
        cipherSuites:
          - ECDHE-RSA-AES256-GCM-SHA384
          - ECDHE-RSA-AES128-GCM-SHA256
      hosts:
        - "api.platform.internal"
    - port:
        number: 80
        name: http
        protocol: HTTP
      tls:
        httpsRedirect: true     # redirect all HTTP to HTTPS
      hosts:
        - "api.platform.internal"
```

Service-to-service traffic is protected by Istio mTLS STRICT mode (see `istio/security/mtls-strict.yaml`).

### 2. Kafka Encryption (Data in Transit)

```properties
# messaging/kafka/server.properties
listeners=SASL_SSL://0.0.0.0:9093
advertised.listeners=SASL_SSL://kafka:9093
ssl.keystore.location=/etc/kafka/ssl/kafka.server.keystore.jks
ssl.keystore.password=${KAFKA_SSL_KEYSTORE_PASSWORD}
ssl.truststore.location=/etc/kafka/ssl/kafka.server.truststore.jks
ssl.truststore.password=${KAFKA_SSL_TRUSTSTORE_PASSWORD}
ssl.client.auth=required
security.inter.broker.protocol=SASL_SSL
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
```

Kafka producer / consumer configuration:

```java
// services/threat-detection-ai (Python) — kafka producer config
producer_config = {
    "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
    "security.protocol": "SASL_SSL",
    "sasl.mechanism": "SCRAM-SHA-512",
    "sasl.username": os.environ["KAFKA_USERNAME"],
    "sasl.password": os.environ["KAFKA_PASSWORD"],
    "ssl.ca.location": "/etc/kafka/ssl/ca-cert.pem",
}
```

### 3. Encryption at Rest — Database

```sql
-- Enable InnoDB tablespace encryption (MySQL 8+)
ALTER TABLE users ENCRYPTION='Y';
ALTER TABLE sessions ENCRYPTION='Y';
ALTER TABLE incidents ENCRYPTION='Y';
```

For Kubernetes-managed databases, use storage class encryption:

```yaml
# k8s/base — PersistentVolumeClaim with encrypted storage class
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mysql-pvc
  namespace: api-security
spec:
  storageClassName: encrypted-ssd   # cloud-provider encrypted storage class
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
```

### 4. Secret Management — No Hardcoded Credentials

The `auth-service/application.yml` contains `security.jwt.secret: your_jwt_secret` — **this must never be deployed**. Use Kubernetes Secrets and mount them as environment variables:

```yaml
# k8s/base/auth-service-deployment.yaml — env from Secret
env:
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: auth-service-secrets
        key: jwt-secret
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: auth-service-secrets
        key: db-password
```

For cloud deployments, use the appropriate secret manager:

```yaml
# terraform/aws — SecretsManager reference
resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "platform/auth-service/jwt-secret"
  recovery_window_in_days = 7
}
```

### 5. Log Masking — Protect PII in ELK

Configure Logstash to mask sensitive fields before indexing:

```ruby
# observability/elk/logstash.conf — sensitive field masking
filter {
  mutate {
    # Remove or hash email and IP addresses before indexing
    gsub => [
      "message", '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', "[EMAIL_REDACTED]",
      "message", '\b(?:\d{1,3}\.){3}\d{1,3}\b', "[IP_REDACTED]"
    ]
    remove_field => ["password", "token", "authorization", "cookie"]
  }
}
```

### 6. Sanitize API Error Responses

Never return stack traces or internal details to clients:

```java
// API Gateway — global exception handler
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex, HttpServletRequest req) {
        // Log detail internally; never expose it externally
        log.error("Unhandled exception on {} {}", req.getMethod(), req.getRequestURI(), ex);
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse("An unexpected error occurred. Reference: " + generateCorrelationId()));
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDataAccess(DataAccessException ex) {
        log.error("Database error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse("A data error occurred."));
    }
}
```

### 7. Minimum Data Retention and Field Minimization

Apply field projection — only fetch and return the data a consumer actually needs:

```java
// UserService — return a DTO, not the full User entity
public UserSummaryDto getUserSummary(Long id) {
    return userRepository.findById(id)
        .map(u -> new UserSummaryDto(u.getId(), u.getDisplayName(), u.getRole()))
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    // Email, passwordHash, mfaSecret are NOT included in UserSummaryDto
}
```

### 8. HTTP Security Headers

Set security headers on all API responses via the API Gateway:

```java
// API Gateway — security header filter
response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
response.setHeader("Cache-Control", "no-store");
response.setHeader("Pragma", "no-cache");
response.setHeader("X-Content-Type-Options", "nosniff");
response.setHeader("Referrer-Policy", "no-referrer");
```

---

## Configuration Checklist

- [ ] TLS 1.2+ enforced on all Istio Gateway listeners
- [ ] mTLS STRICT mode active for all service-to-service traffic
- [ ] Kafka listeners use `SASL_SSL` only
- [ ] Database tables with PII use encryption at rest
- [ ] No secrets in `application.yml`, `bootstrap.yml`, or any committed config file
- [ ] Kubernetes Secrets / cloud secret manager in use for all credentials
- [ ] Logstash pipeline masks email addresses, IPs, auth tokens before indexing
- [ ] API error responses return generic messages (no stack traces)
- [ ] `Strict-Transport-Security` header set with preload directive
- [ ] Sensitive fields excluded from DTO projections

---

## Testing
```text
| Test Type | Tool | Coverage |
|-----------|------|----------|
| Secret scanning | `truffleHog` / `gitleaks` in CI | Committed secrets detection |
| TLS validation | `testssl.sh` | Cipher suite and protocol checks |
| DAST | OWASP ZAP | Sensitive data in responses |
| Log review | Manual / ELK query | PII leakage in log indices |
```
---

## Platform Files
```text
| File | Purpose |
|------|---------|
| `istio/gateways/api-ingress-gateway.yaml` | TLS termination at ingress |
| `istio/security/mtls-strict.yaml` | mTLS enforcement |
| `messaging/kafka/server.properties` | Kafka TLS/SASL configuration |
| `observability/elk/logstash.conf` | Log pipeline (add masking filters) |
| `ci-cd/github-actions/security-scan.yml` | CI secret scanning step |
```
---

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
