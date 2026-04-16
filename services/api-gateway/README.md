# API Gateway

## Overview
The API Gateway acts as the single entry point for all client requests to the microservices ecosystem. It provides centralized security, routing, rate limiting, and observability. It integrates with Istio for service mesh capabilities and enforces security policies such as JWT validation and input sanitization.

## Key Responsibilities
- Centralized routing to backend services
- Authentication and authorization (JWT, OAuth2)
- Input validation and sanitization
- Rate limiting and throttling
- Logging and API monitoring
- Integration with Istio Ingress Gateway
- Publishing API logs to Kafka for threat detection

## Main Functions
- **Route Requests:** Forwards incoming API requests to the appropriate microservice based on path and method.
- **Security Enforcement:** Validates JWT tokens, applies input sanitization, and enforces rate limits.
- **Observability:** Logs all API requests and responses, and publishes logs to Kafka topics for downstream analysis.

Routing configuration is defined in YAML:

- `src/main/resources/application.yml` for host/local defaults
- `src/main/resources/application-docker.yml` for docker profile targets

`GatewayConfig.java` is used for CORS settings.

## Flow
1. Client sends API request to the API Gateway endpoint.
2. Gateway authenticates the request (JWT/OAuth2).
3. Applies input validation and rate limiting.
4. Forwards the request to the correct backend service via Istio routing.
5. Logs the request/response and publishes to Kafka (`api-logs` topic).
6. Returns the backend response to the client.

## Technologies

- Java 21
- Spring Boot (Microservices Architecture)
- Spring WebFlux (Reactive API Gateway)
- Spring Security (JWT-based authentication & authorization)
- JWT (jjwt) for secure token management
- Apache Kafka (Event-driven security pipeline)

## Folder Structure
```
services/api-gateway/
├── Dockerfile
├── pom.xml
├── README.md
│
├── src/
│   ├── main/
│   │   ├── java/com/api/security/gateway/
│   │   │   ├── ApiGatewayApplication.java
│   │   │
│   │   │   ├── config/
│   │   │   │   ├── GatewayConfig.java
│   │   │   │   └── SecurityConfig.java
│   │   │
│   │   │   ├── filter/
│   │   │   │   ├── JwtAuthenticationFilter.java
│   │   │   │   └── LoggingFilter.java
│   │   │
│   │   │   ├── util/
│   │   │   │   └── JwtUtil.java
│   │   │
│   │   │   └── exception/
│   │   │       └── GlobalExceptionHandler.java
│   │
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-docker.yml
│   │       └── logback.xml
│   │
│   └── test/
│       └── java/com/api/security/gateway/
│           └── ApiGatewayApplicationTests.java

```

## Postman Tests

### Health Check
```
GET http://localhost:8080/api/health
```

### Proxy to User Service
```
GET http://localhost:8080/users?email=test@example.com
```

### Common Route Mistake

`/users/api/health` is not a valid endpoint. Use:

- `GET /api/health`
- `GET /users?email=<value>`

- For protected endpoints, set the `Authorization: Bearer <JWT>` header.
