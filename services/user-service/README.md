# User Service

## Overview

The User Service handles user-facing read operations and publishes security-relevant events to Kafka. In this platform, it acts as both a business endpoint and an input source for threat detection.

## What It Does

- Exposes the `/users` API.
- Accepts an `email` query parameter and returns a simple user lookup response.
- Publishes request context to Kafka topic `api-logs` for downstream analysis.

## API Endpoint

### Get User

```
GET /users?email=<value>
```

Example:

```
GET /users?email=test@example.com
```

Expected response:

```
User fetched: test@example.com
```

## Kafka Behavior

- Topic: `api-logs`
- Purpose: stream request payloads into the security pipeline
- Downstream consumers: `threat-detection-ai` and observability components

## Runtime Notes

- Service port: `8081`
- In local end-to-end testing, this endpoint is usually reached through gateway route:
  - `http://localhost:8080/users?email=test@example.com`

## Local Run

```bash
mvn clean package -DskipTests
java -jar target/user-service-1.0.0.jar
```

## Role In Platform Flow

1. Request reaches gateway and is routed to user-service.
2. User-service processes the request.
3. Event is published to `api-logs`.
4. Threat detection pipeline consumes and evaluates the event.
