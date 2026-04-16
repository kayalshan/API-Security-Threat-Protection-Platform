# Kafka Failure Recovery Runbook

## Purpose

This runbook covers Kafka-related outages and degradations for the platform's event pipeline.

Kafka is not just a transport detail in this project. It connects operational security controls:

- `api-logs`: activity from user-facing services into Threat Detection AI
- `threat-alerts`: AI detections into Remediation Service
- `security-events`: security events into downstream audit consumers
- `audit-logs`: broad platform audit stream into observability tooling

If Kafka fails, the user-facing API may still appear partially healthy while detection and remediation are silently degraded. Treat that as a production-impacting condition.

## Supported Topology in This Repository

- Local and demo mode: single-node Kafka in KRaft mode
- Local broker address inside containers: `kafka:9092`
- Local host exposure: `localhost:9092`
- Default topic creation script: `./scripts/create-topics.sh`
- Local compose definition: `docker-compose.yml`

## Failure Modes

### Broker unavailable

Symptoms:

- Services log connection refused or timeout errors to Kafka
- Topic listing fails
- Threat Detection AI and Remediation Service stop processing

### Topic missing or misconfigured

Symptoms:

- Producers log unknown topic errors
- Consumers idle unexpectedly
- Some event types flow while others stop

### Consumer stalled

Symptoms:

- Broker is healthy but events do not progress
- Threat Detection AI or Remediation Service logs stop advancing
- User Service continues to serve requests while detection falls behind

### Data directory or cluster metadata problem

Symptoms:

- Kafka container restarts repeatedly
- KRaft cluster ID mismatch or storage initialization errors
- Recovery fails until local metadata is cleared

## First-Line Diagnostics

### Docker Compose Environment

```bash
docker compose ps
docker compose logs --tail=200 kafka
docker compose logs --tail=200 user-service threat-detection-ai remediation-service api-gateway auth-service
```

### Broker Reachability

```bash
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --list
```

### Expected Topics

Expected topic set:

- `api-logs`
- `threat-alerts`
- `security-events`
- `audit-logs`

### Topic Recreation

```bash
./scripts/create-topics.sh
```

The repository topic creation script creates all four topics with `3` partitions and replication factor `1`.

## Triage Flow

### 1. Is the broker process up?

```bash
docker inspect -f '{{.State.Running}}' kafka
docker compose logs --tail=200 kafka
```

If the broker is down, recover the broker first. Do not spend time on consumer debugging until topic listing works.

### 2. Can the broker answer metadata requests?

```bash
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --list
```

If this fails, the broker is not ready or is not accepting connections.

### 3. Are the required topics present?

```bash
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --describe --topic api-logs
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --describe --topic threat-alerts
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --describe --topic security-events
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --describe --topic audit-logs
```

If a topic is missing, recreate it with the standard script.

### 4. Are producers and consumers healthy?

Check logs in this order:

1. `user-service` for failures publishing `api-logs`
2. `threat-detection-ai` for failures consuming `api-logs` or publishing `threat-alerts`
3. `remediation-service` for failures consuming `threat-alerts`
4. `api-gateway` and `auth-service` for failures emitting `security-events`

## Recovery Procedures

### Recover a Stopped Broker

```bash
docker compose up -d kafka
docker compose logs -f kafka
docker exec kafka kafka-topics --bootstrap-server kafka:9092 --list
```

Once listing works, recreate or verify topics and then check consumer services.

### Recreate Topics Safely

```bash
./scripts/create-topics.sh
```

The script is idempotent through `--if-not-exists`. Use it before ad hoc topic creation to keep partition counts consistent.

### Restart Pipeline Services After Broker Recovery

```bash
docker compose restart user-service threat-detection-ai remediation-service api-gateway auth-service
docker compose logs --tail=200 user-service threat-detection-ai remediation-service
```

Restart only the services that show persistent connection failures. Prefer targeted restarts over full stack recycling.

### Recover from KRaft Metadata Corruption or Cluster ID Mismatch

Use this only when Kafka cannot start cleanly because local metadata is corrupted or incompatible.

```bash
./scripts/cleanup.sh --yes
./scripts/deploy-all.sh local
```

Important consequences:

- This is destructive for local Kafka state.
- The cleanup script removes the `kafka_data` volume.
- Any local-only retained events are lost.

Do not use this flow in a production Kafka environment without a platform-approved data recovery procedure.

## Validation After Recovery

Validate all of the following before closing the incident:

1. `docker exec kafka kafka-topics --bootstrap-server kafka:9092 --list` returns the expected topic set.
2. `GET /api/health` succeeds through the local or ingress endpoint.
3. A login request succeeds.
4. A `GET /users?email=<value>` request succeeds through gateway using the expected profile policy.
5. Threat Detection AI logs show new work arriving from `api-logs`.
6. Remediation Service logs show resumed consumption of `threat-alerts`.

## Prevention and Hardening

Before relying on this stack outside development or showcase use, ensure the deployment plan includes:

- Multi-broker Kafka with replication greater than `1`
- Persistent storage with a tested recovery policy
- Consumer lag monitoring and alerting
- Broker health alerts
- Topic configuration under version control for each environment
- Clear retention, replay, and data loss acceptance policies

## Escalate When

- The broker repeatedly fails after clean restart
- Topic recreation succeeds but no consumers resume work
- Threat alerts are being dropped during an active security event
- Recovery requires storage-level intervention beyond the local compose workflow
