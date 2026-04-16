# Auth Service

## Overview

The Auth Service handles login and token verification for the platform. It issues JWT tokens for valid credentials and exposes a validation endpoint used by other components during request flow.

## Key Responsibilities

- User authentication (username/password, OAuth2, etc.)
- JWT token generation and validation
- Exposing login and token validation endpoints
- Integrating with API Gateway and Istio for secure communication
- Logging authentication events to Kafka

## Main Functions

- Authenticate user credentials and return JWT tokens.
- Validate incoming JWT tokens.
- Emit security-related authentication events.

## Flow

1. Client submits login credentials to the Auth Service.
2. Service validates credentials against the user store.
3. On success, generates a JWT token and returns it to the client.
4. Publishes authentication event to Kafka.
5. API Gateway and other services validate JWT tokens using this service.

## Technologies
- Java 21
- Spring Boot, Spring WebFlux
- Spring Security
- JWT (Java JWT, jjwt)
- Kafka

## Folder Structure
```
services/auth-service/
├── Dockerfile
├── pom.xml
├── README.md
├── src/
│   ├── main/java/com/api/security/auth/
│   │   ├── AuthServiceApplication.java
│   │   ├── controller/
│   │   │   └── AuthController.java
│   │   ├── service/
│   │   │   └── AuthService.java
│   │   ├── util/
│   │   │   └── JwtUtil.java
│   │   ├── model/
│   │   │   └── AuthRequest.java
│   │   └── config/
│   │       └── SecurityConfig.java
│   └── resources/
│       └── application.yml
```

## Postman Tests

### Login

```
POST http://localhost:8082/auth/login
Content-Type: application/json
{
  "username": "admin",
  "password": "password"
}
```

### Validate Token

```
POST http://localhost:8082/auth/validate
Authorization: Bearer <JWT>
```

### Gateway Path (recommended for end-to-end testing)

```
POST http://localhost:8080/auth/login
POST http://localhost:8080/auth/validate
```
