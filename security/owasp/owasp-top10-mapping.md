# OWASP Top 10 Mapping

This document maps each OWASP Top 10 risk to its detailed guidance file, primary platform components affected, and the key controls applied in this platform.

> **OWASP Version:** 2021 (A01–A10)
> **Platform:** Unified API Security Threat Protection Platform
> **Last Reviewed:** March 2026

---

## Risk Overview Table

```text

| Risk ID | OWASP 2021 Category | Description | Severity | Platform File |
|---------|---------------------|-------------|----------|---------------|
| A1 | Injection | SQL, NoSQL, OS, LDAP injection via untrusted data | Critical | [sql-injection-prevention.md](sql-injection-prevention.md) |
| A2 | Broken Authentication | Weak credentials, token mismanagement, missing MFA | Critical | [broken-authentication.md](broken-authentication.md) |
| A3 | Sensitive Data Exposure | Missing encryption, secrets in code, PII in logs | High | [sensitive-data-exposure.md](sensitive-data-exposure.md) |
| A4 | XML External Entities (XXE) | Misconfigured XML parsers process external entity refs | High | [xxe-prevention.md](xxe-prevention.md) |
| A5 | Broken Access Control | IDOR, missing function-level auth, CORS misconfiguration | Critical | [broken-access-control.md](broken-access-control.md) |
| A6 | Security Misconfiguration | Insecure defaults, unnecessary features, verbose errors | High | [security-misconfiguration.md](security-misconfiguration.md) |
| A7 | Cross-Site Scripting (XSS) | Unescaped user data executed in victim's browser | High | [xss-protection.md](xss-protection.md) |
| A8 | Insecure Deserialization | Malicious serialized objects trigger RCE or logic bypass | Critical | [insecure-deserialization.md](insecure-deserialization.md) |
| A9 | Vulnerable Components | Outdated libraries/containers with known CVEs | High | [vulnerable-components.md](vulnerable-components.md) |
| A10 | Insufficient Logging & Monitoring | Missing audit trail, no alerting, slow breach detection | Medium | [insufficient-logging-monitoring.md](insufficient-logging-monitoring.md) |
```
---

## Platform Controls Summary
```text
| OWASP Risk | Istio / Mesh | WAF (ModSecurity) | Spring Security | Kafka / Messaging | Observability |
|------------|-------------|-------------------|-----------------|-------------------|---------------|
| A1 Injection | — | CRS SQLi rules (942) | Input validation, ORM | Schema validation | Alert on WAF blocks |
| A2 Broken Auth | mTLS + RequestAuthentication | Rate limiting | JwtValidationFilter, BCrypt | SASL auth | Auth failure alerts |
| A3 Data Exposure | TLS termination, mTLS | — | Error handler sanitization | SASL_SSL encryption | Log PII masking |
| A4 XXE | Block XML content-type | Custom DOCTYPE rules | Safe XML parser config | Avro over XML | Log parser errors |
| A5 Access Control | AuthorizationPolicy RBAC | — | @PreAuthorize, default-deny | Kafka ACLs | Access denied alerts |
| A6 Misconfiguration | mTLS STRICT | CRS enforcement | Prod profile, actuator lockdown | ACLs, SASL_SSL | Config change alerts |
| A7 XSS | — | CRS XSS rules (941) | Output encoding, CSP headers | — | WAF block alerts |
| A8 Deserialization | Block octet-stream | Block x-java-serialized | Jackson hardening, @Valid | Avro + Schema Registry | Deserialization error alerts |
| A9 Vulnerable Components | Istio version tracking | CRS updates | OWASP Dep Check, BOM | Kafka client patching | CVE pipeline alerts |
| A10 Logging & Monitoring | Envoy access logs | WAF audit log | SecurityAuditLogger, correlation IDs | Kafka message tracing | Prometheus + ELK + Grafana |
```
---

## Related Platform Files

```text

| File / Directory | OWASP Risk(s) Addressed |
|-----------------|-------------------------|
| `security/api-security/JwtValidationFilter.java` | A2, A5 |
| `security/api-security/InputSanitization.java` | A1, A7 |
| `security/api-security/rate-limiter-config.yaml` | A2, A5 |
| `security/waf/modsecurity.conf` | A1, A6, A7 |
| `security/waf/owasp-crs.conf` | A1, A4, A7, A8 |
| `security/waf/custom-rules.conf` | A1, A4, A7, A8 |
| `istio/security/mtls-strict.yaml` | A2, A3, A6 |
| `istio/security/request-authentication.yaml` | A2, A5 |
| `istio/security/authorization-policy.yaml` | A5, A6 |
| `messaging/kafka/server.properties` | A3, A6 |
| `observability/elk/logstash.conf` | A3, A10 |
| `observability/prometheus/prometheus-config.yaml` | A10 |
| `ci-cd/github-actions/security-scan.yml` | A9, A1, A7 |
| `docs/runbooks/incident-response.md` | A10 |
| `docs/threat-model/threat-model.md` | All |

```
---

## Compliance Mapping

```text

| OWASP Risk | PCI DSS | ISO 27001 | NIST SP 800-53 | SOC 2 |
|------------|---------|-----------|----------------|-------|
| A1 Injection | Req 6.3 | A.14.2.5 | SI-10 | CC6.1 |
| A2 Broken Auth | Req 8 | A.9.4 | IA-2, IA-5 | CC6.1, CC6.2 |
| A3 Data Exposure | Req 3, 4 | A.10.1 | SC-8, SC-28 | CC6.1, CC6.7 |
| A4 XXE | Req 6.5.4 | A.14.2.5 | SI-10 | CC6.1 |
| A5 Access Control | Req 7 | A.9.1 | AC-2, AC-3 | CC6.1, CC6.3 |
| A6 Misconfiguration | Req 2, 6.4 | A.12.1.1 | CM-6, CM-7 | CC6.1, CC6.6 |
| A7 XSS | Req 6.5.7 | A.14.2.5 | SI-10 | CC6.1 |
| A8 Deserialization | Req 6.5.8 | A.14.2.5 | SI-10 | CC6.1 |
| A9 Vuln. Components | Req 6.2, 6.3 | A.12.6.1 | RA-5, SI-2 | CC7.1 |
| A10 Logging & Monitoring | Req 10 | A.12.4 | AU-2, AU-3, IR-4 | CC7.2, CC7.3 |

```