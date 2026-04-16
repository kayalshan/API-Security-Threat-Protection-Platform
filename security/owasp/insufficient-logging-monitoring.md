# A10 – Insufficient Logging & Monitoring

## Overview

Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days — typically detected by external parties rather than internal processes or monitoring.

In this platform, the observability stack (ELK, Prometheus, Grafana) and Kafka event pipeline provide the infrastructure for comprehensive security logging. However, logging without proper content, alerting without response procedures, and gaps in coverage all constitute this risk.

**OWASP Reference:** [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

---

## What Must Be Logged
```text
| Event Category | Examples | Minimum Fields Required |
|---------------|----------|------------------------|
| Authentication | Login success/failure, logout, MFA events | timestamp, user_id, ip_address, user_agent, outcome |
| Authorization | Access denied, role changes, privilege escalation | timestamp, user_id, resource, action, outcome |
| Threat Detection | Detected threats, severity, model score | timestamp, threat_type, severity, source_ip, mitre_tactic |
| Remediation Actions | Blocking an IP, quarantining an account, rule changes | timestamp, admin_id, action, target, justification |
| Input Validation Failures | Injection attempt, XSS payload, oversized input | timestamp, endpoint, input_field, pattern_matched |
| Configuration Changes | Secret rotation, WAF rule updates, deployment | timestamp, admin_id, change_type, before, after |
| Data Access | Bulk data export, access to sensitive records | timestamp, user_id, resource_id, record_count |
| System Errors | Unhandled exceptions, DB connection failures | timestamp, service, error_class, correlation_id (no stack trace to client) |

```

---

## Prevention Controls

### 1. Structured JSON Logging (All Java Services)

Use Logback with a JSON encoder to produce machine-readable logs consumable by the ELK stack:

```xml
<!-- services/*/src/main/resources/logback-spring.xml -->
<configuration>
    <springProfile name="prod">
        <appender name="JSON_CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
            <encoder class="net.logstash.logback.encoder.LogstashEncoder">
                <includeMdcKeyName>correlationId</includeMdcKeyName>
                <includeMdcKeyName>userId</includeMdcKeyName>
                <includeMdcKeyName>requestPath</includeMdcKeyName>
                <includeMdcKeyName>clientIp</includeMdcKeyName>
                <!-- Never include password, token, or secret MDC keys -->
            </encoder>
        </appender>
        <root level="INFO">
            <appender-ref ref="JSON_CONSOLE"/>
        </root>
    </springProfile>
</configuration>
```

Dependency:

```xml
<dependency>
    <groupId>net.logstash.logback</groupId>
    <artifactId>logstash-logback-encoder</artifactId>
    <version>7.4</version>
</dependency>
```

### 2. Security Event Logging — Dedicated Logger

Create a dedicated security event logger that always logs at `WARN` or higher and streams to a separate index:

```java
// services/api-gateway/src — SecurityAuditLogger.java
@Component
public class SecurityAuditLogger {

    private static final Logger SECURITY_LOG =
        LoggerFactory.getLogger("SECURITY_AUDIT");

    public void logAuthSuccess(String userId, String ipAddress, String userAgent) {
        SECURITY_LOG.info("AUTH_SUCCESS userId={} ip={} userAgent={}",
            userId, maskSensitive(ipAddress), sanitize(userAgent));
    }

    public void logAuthFailure(String username, String ipAddress, String reason) {
        SECURITY_LOG.warn("AUTH_FAILURE username={} ip={} reason={}",
            maskField(username), maskSensitive(ipAddress), reason);
    }

    public void logAccessDenied(String userId, String resource, String action) {
        SECURITY_LOG.warn("ACCESS_DENIED userId={} resource={} action={}",
            userId, resource, action);
    }

    public void logThreatDetected(String threatType, String severity, String sourceIp,
                                   String mitreTactic, double modelScore) {
        SECURITY_LOG.error("THREAT_DETECTED type={} severity={} sourceIp={} tactic={} score={}",
            threatType, severity, maskSensitive(sourceIp), mitreTactic,
            String.format("%.3f", modelScore));
    }

    public void logRemediationAction(String adminId, String action, String target,
                                      String justification) {
        SECURITY_LOG.warn("REMEDIATION_ACTION adminId={} action={} target={} reason={}",
            adminId, action, target, justification);
    }

    private String maskSensitive(String value) {
        // Mask last two octets of IPv4 for PII compliance while preserving utility
        if (value != null && value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return value.replaceAll("(\\d+\\.\\d+)\\.\\d+\\.\\d+", "$1.xxx.xxx");
        }
        return value;
    }

    private String maskField(String value) {
        if (value == null || value.length() < 3) return "***";
        return value.substring(0, 2) + "***";
    }

    private String sanitize(String value) {
        return value == null ? "" : value.replaceAll("[\r\n]", "_"); // prevent log injection
    }
}
```

### 3. Correlation IDs — Trace Across Services

Every request must carry a correlation ID propagated through all service calls and Kafka messages:

```java
// API Gateway — correlation ID filter
@Component
@Order(1)
public class CorrelationIdFilter implements Filter {

    private static final String CORRELATION_HEADER = "X-Correlation-ID";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String correlationId = httpRequest.getHeader(CORRELATION_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }
        // Add to MDC for structured logging
        MDC.put("correlationId", correlationId);
        ((HttpServletResponse) response).setHeader(CORRELATION_HEADER, correlationId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("correlationId");
        }
    }
}
```

Propagate correlation ID in Kafka message headers:

```java
// Kafka producer — include correlation ID in message headers
ProducerRecord<String, ThreatEvent> record = new ProducerRecord<>(
    "threat-events", event.getId().toString(), event);
record.headers().add("X-Correlation-ID",
    MDC.get("correlationId").getBytes(StandardCharsets.UTF_8));
kafkaTemplate.send(record);
```

### 4. Logstash Pipeline — Security Index and Enrichment

```ruby
# observability/elk/logstash.conf — security event pipeline
input {
  beats {
    port => 5044
  }
}

filter {
  # Parse JSON logs from all services
  json {
    source => "message"
    target => "parsed"
    skip_on_invalid_json => true
  }

  # Route security audit events to dedicated index
  if [parsed][logger_name] == "SECURITY_AUDIT" {
    mutate { add_field => { "[@metadata][target_index]" => "security-audit" } }
  } else {
    mutate { add_field => { "[@metadata][target_index]" => "application-logs" } }
  }

  # Mask PII before indexing
  mutate {
    gsub => [
      "message", '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
               "[EMAIL_REDACTED]"
    ]
    remove_field => ["password", "token", "authorization", "cookie", "secret"]
  }

  # Add GeoIP enrichment for source IPs (threat analysis)
  if [parsed][sourceIp] {
    geoip {
      source => "[parsed][sourceIp]"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["${ELASTICSEARCH_URL}"]
    index => "%{[@metadata][target_index]}-%{+YYYY.MM.dd}"
    user => "${ES_USER}"
    password => "${ES_PASSWORD}"
    ssl => true
    cacert => "/etc/ssl/certs/ca-bundle.crt"
  }
}
```

### 5. Prometheus Alerting — Real-Time Security Alerts

```yaml
# observability/prometheus/prometheus-config.yaml — alerting rules
groups:
  - name: security_alerts
    rules:
      - alert: HighAuthFailureRate
        expr: |
          rate(auth_failures_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "High authentication failure rate detected"
          description: "{{ $value | humanize }} auth failures/sec — possible brute force or credential stuffing"

      - alert: ThreatDetectedCritical
        expr: |
          increase(threats_detected_total{severity="CRITICAL"}[1m]) > 0
        for: 0m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Critical threat detected"
          description: "A CRITICAL severity threat event was detected. Immediate review required."

      - alert: RemediationServiceDown
        expr: up{job="remediation-service"} == 0
        for: 1m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Remediation service is unreachable"

      - alert: UnusualDataExport
        expr: |
          increase(data_export_records_total[10m]) > 1000
        for: 0m
        labels:
          severity: high
          team: security
        annotations:
          summary: "Unusual bulk data export detected"
          description: "{{ $value }} records exported in 10 minutes by a single user"

      - alert: WAFBlockSpike
        expr: |
          rate(waf_blocked_requests_total[5m]) > 50
        for: 3m
        labels:
          severity: high
          team: security
        annotations:
          summary: "Spike in WAF-blocked requests"
          description: "More than 50 requests/sec being blocked — possible attack in progress"
```

### 6. Kibana — Security Dashboard

Import the pre-built Kibana dashboard (`observability/elk/kibana-dashboard.ndjson`) and ensure it includes:

```text
| Panel | Data Source | Alert Threshold |
|-------|-------------|-----------------|
| Auth failures by IP (last 24h) | `security-audit-*` | > 20 failures same IP |
| Threat severity distribution | `security-audit-*` | Any CRITICAL |
| Blocked requests by WAF rule | `nginx-access-*` | > 500 blocks/hour |
| Failed access control checks | `security-audit-*` | > 50/hour |
| Remediation actions timeline | `security-audit-*` | Any unexpected action |
| Top 10 source IPs (threats) | `security-audit-*` | Correlation with GeoIP |
```

### 7. Log Integrity — Tamper Detection

Security logs must be protected from modification:

```yaml
# k8s/base — mount log storage as ReadOnly for application pods
# Logs are written to stdout (collected by Filebeat) — not to local filesystem
# Filebeat DaemonSet collects stdout and forwards to Logstash

# Elasticsearch index lifecycle — make security-audit indices read-only after 24h
PUT /_ilm/policy/security-audit-policy
{
  "policy": {
    "phases": {
      "hot": { "actions": { "rollover": { "max_age": "1d" } } },
      "frozen": {
        "min_age": "1d",
        "actions": { "freeze": {} }   // read-only, compressed
      },
      "delete": { "min_age": "365d", "actions": { "delete": {} } }
    }
  }
}
```

### 8. Incident Response Integration

Link Prometheus/Grafana alerts to the incident response runbook:

```yaml
# observability/grafana — alertmanager configuration
receivers:
  - name: security-team
    pagerduty_configs:
      - service_key: "${PAGERDUTY_SERVICE_KEY}"
        description: "{{ .GroupLabels.alertname }}: {{ .Annotations.description }}"
    slack_configs:
      - api_url: "${SLACK_WEBHOOK_URL}"
        channel: "#security-incidents"
        title: "SECURITY ALERT: {{ .GroupLabels.alertname }}"
        text: "{{ .Annotations.description }}\nRunbook: https://wiki.internal/runbooks/{{ .GroupLabels.alertname }}"
```

Reference incident response procedures: [docs/runbooks/incident-response.md](../../docs/runbooks/incident-response.md)

---

## Log Injection Prevention

Prevent attackers from injecting fake log entries by sanitizing all user-controlled values before logging:

```java
// Sanitize before logging — strip CRLF and control characters
private String sanitizeForLog(String value) {
    if (value == null) return "null";
    return value
        .replaceAll("[\r\n\t]", "_")           // strip line breaks (log injection)
        .replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "")  // strip other control chars
        .replaceAll("(?i)(password|secret|token)=[^&\\s]+", "$1=***");  // mask secrets
}
```

---

## Configuration Checklist

- [ ] All services produce structured JSON logs via Logback + Logstash encoder
- [ ] SecurityAuditLogger (or equivalent) logs auth, authz, threat, and remediation events
- [ ] Correlation ID injected into MDC and propagated in Kafka message headers
- [ ] Logstash pipeline routes `SECURITY_AUDIT` events to a dedicated index
- [ ] PII (email, IP) masked in Logstash pipeline before Elasticsearch indexing
- [ ] Prometheus alert rules cover: auth failure rate, critical threats, WAF spikes, data exports
- [ ] Grafana/PagerDuty/Slack alerting configured for all CRITICAL and HIGH alerts
- [ ] Log entries never include passwords, tokens, full IPs without masking
- [ ] Log injection prevention (CRLF sanitization) applied before all logging calls
- [ ] Elasticsearch `security-audit` indices frozen (read-only) after 24 hours
- [ ] Security logs retained for ≥ 365 days per compliance requirements
- [ ] `docs/runbooks/incident-response.md` linked from alert annotations

---

## Testing

| Test Type | Tool | Coverage |
|-----------|------|----------|
| Log completeness | Manual / Postman | Trigger each event type; verify corresponding log entry |
| Alert validation | Prometheus `amtool` | Fire test alerts; confirm PagerDuty/Slack receive them |
| Log injection | ZAP / manual | Submit CRLF payloads in all input fields |
| Log PII audit | Elasticsearch query | Scan for email/IP patterns in application-logs index |
| Retention check | Elasticsearch ILM status | Verify frozen phase applied, delete policy active |

---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `observability/elk/logstash.conf` | Log pipeline with enrichment and PII masking |
| `observability/elk/filebeat.yml` | Log collection from pod stdout |
| `observability/elk/kibana-dashboard.ndjson` | Pre-built security dashboards |
| `observability/prometheus/prometheus-config.yaml` | Alerting rules |
| `observability/grafana/dashboards/` | Grafana dashboard definitions |
| `docs/runbooks/incident-response.md` | Incident response procedures |
```
---

## References

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Application Logging Vocabulary](https://owasp.org/www-project-developer-guide/draft/design/web_app_checklist/logging/)
- [OWASP Log Injection](https://owasp.org/www-community/attacks/Log_Injection)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
