# Remediation Service

## Overview
The Remediation Service listens for threat alerts from Kafka and takes automated actions to mitigate or block detected threats. It can update WAF rules, trigger Istio policy changes, or notify administrators. This enables real-time, closed-loop security response.

## Key Responsibilities
- Consuming threat alerts from Kafka (`threat-alerts` topic)
- Automated remediation actions (WAF, Istio, notifications)
- Updating security policies dynamically
- Logging remediation actions for audit

## Main Functions
- **Consume Alerts:** Listens to the `threat-alerts` Kafka topic for new threat alerts.
- **Remediate:** Applies automated actions such as updating WAF rules, blocking IPs, or changing Istio policies.
- **Log Actions:** Records all remediation steps for compliance and audit.

## Flow
1. Service consumes threat alerts from Kafka.
2. Determines the appropriate remediation action based on alert type.
3. Updates WAF rules, Istio policies, or notifies admins as needed.
4. Logs all actions for traceability.

## Example Technologies
- Python (Flask, FastAPI)
- Kafka
- Integration with ModSecurity, Istio, email/SMS APIs

## Folder Structure
```
remediation-service/
├── Dockerfile
├── remediation-app.py
├── remediation-kafka_consumer.py
├── remediation-waf_updater.py
└── README.md
```

## Postman Tests

### Health Check (if API exposed)
```
GET http://localhost:6000/health
```

### Simulate Threat Alert (Kafka)
- Use Kafka tools or scripts to publish a test alert to the `threat-alerts` topic.
