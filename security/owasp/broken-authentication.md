# A2 – Broken Authentication

## Overview

Broken Authentication occurs when application functions related to authentication and session management are implemented incorrectly, allowing attackers to compromise passwords, session tokens, or exploit implementation flaws to assume other users' identities temporarily or permanently.

In this platform the Auth-Service issues and validates JWTs for all inter-service and external API calls. Istio mTLS secures service-to-service communication. Weaknesses in either layer create an authentication gap across every downstream service.

**OWASP Reference:** [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

## Attack Vectors

```text

| Vector | Description | Platform Exposure |
|--------|-------------|-------------------|
| Credential Stuffing | Automated use of breached username/password pairs | API Gateway `/auth/**` endpoints |
| Brute Force | Repeated password guesses | Auth-Service login endpoint |
| Weak JWT Secret | Token forged with a guessable secret | Auth-Service JWT issuance |
| Token Not Invalidated | Logout does not revoke server-side session | Auth-Service session store |
| Session Fixation | Attacker sets a known session ID before login | API Gateway cookie handling |
| Missing Token Expiry | Long-lived tokens extend attacker window | JWT `exp` claim |
| Cleartext Credentials | Credentials transmitted without TLS | Istio gateway if mTLS disabled |
```

---

## Prevention Controls

### 1. Strong JWT Configuration

The platform issues JWTs via `JwtValidationFilter.java`. Ensure the following:

```java
// Auth-Service — JWT configuration (application.yml)
// security.jwt.secret must be a random 256-bit value loaded from a secret manager,
// NOT hardcoded as shown in the example application.yml

@Value("${security.jwt.secret}")
private String jwtSecret;

public String generateToken(String username, List<String> roles) {
    return Jwts.builder()
        .setSubject(username)
        .claim("roles", roles)
        .setIssuedAt(new Date())
        .setExpiration(Date.from(Instant.now().plus(Duration.ofMinutes(15))))  // short-lived
        .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)),
                  SignatureAlgorithm.HS256)
        .compact();
}
```

**Required JWT hardening:**

```text

| Setting | Recommended Value | Rationale |
|---------|------------------|-----------|
| Algorithm | `HS256` / `RS256` | Avoid `none` or weak algorithms |
| Secret length | ≥ 256-bit random | Resist brute-force |
| Access token TTL | 15 minutes | Reduce stolen-token window |
| Refresh token TTL | 7 days, rotated | Balance UX and security |
| `jti` claim | UUID per token | Enable token revocation |

```

### 2. JWT Validation Filter

The `JwtValidationFilter` must perform all of the following checks:

```java
public class JwtValidationFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Missing or malformed Authorization header");
            return;
        }

        String token = authHeader.substring(7);
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();

            // Validate expiry (automatic with jjwt), issuer, and audience
            if (!EXPECTED_ISSUER.equals(claims.getIssuer())) {
                throw new JwtException("Invalid issuer");
            }

            // Check revocation list (Redis-backed blacklist)
            if (tokenBlacklist.isRevoked(claims.getId())) {
                throw new JwtException("Token has been revoked");
            }

            request.setAttribute("claims", claims);
            chain.doFilter(request, response);
        } catch (JwtException e) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Invalid or expired token");
        }
    }
}
```

### 3. Rate Limiting on Authentication Endpoints

Use the platform rate limiter (`security/api-security/rate-limiter-config.yaml`) to throttle login attempts and block credential stuffing:

```yaml
# rate-limiter-config.yaml — auth-specific override
rate-limiter:
  enabled: true
  routes:
    - path: /auth/login
      requests-per-minute: 10        # strict limit on login
      burst-capacity: 3
      lockout-after-failures: 5
      lockout-duration-seconds: 300
    - path: /auth/token/refresh
      requests-per-minute: 20
      burst-capacity: 5
```

### 4. Istio mTLS — Service-to-Service Authentication

All service-to-service calls must use mTLS (enforced via `istio/security/mtls-strict.yaml`):

```yaml
# istio/security/mtls-strict.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: api-security
spec:
  mtls:
    mode: STRICT   # no plaintext allowed between services
```

### 5. Istio RequestAuthentication (External JWTs)

```yaml
# istio/security/request-authentication.yaml
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: api-security
spec:
  selector:
    matchLabels:
      app: api-gateway
  jwtRules:
    - issuer: "https://auth.platform.internal"
      jwksUri: "https://auth.platform.internal/.well-known/jwks.json"
      forwardOriginalToken: true
```

### 6. Secure Password Storage

Auth-Service must use an adaptive hashing algorithm:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    // BCrypt with cost factor 12; re-tune as hardware improves
    return new BCryptPasswordEncoder(12);
}

// During registration
user.setPasswordHash(passwordEncoder.encode(rawPassword));

// During login
if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
    throw new BadCredentialsException("Invalid credentials");
}
```

### 7. Multi-Factor Authentication (MFA)

For privileged operations (admin endpoints, remediation actions), enforce TOTP-based MFA:

```java
public boolean verifyTotp(String secret, int userCode) {
    TimeProvider timeProvider = new SystemTimeProvider();
    CodeGenerator codeGenerator = new DefaultCodeGenerator();
    CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    verifier.setAllowedTimePeriodDiscrepancy(1); // allow ±1 period clock skew
    return verifier.isValidCode(secret, userCode);
}
```

### 8. Token Revocation (Logout)

On logout, add the token's `jti` to a Redis-backed blacklist:

```java
public void logout(String token) {
    Claims claims = parseToken(token);
    long remainingTtl = claims.getExpiration().getTime() - System.currentTimeMillis();
    redisTemplate.opsForValue().set(
        "revoked:" + claims.getId(),
        "1",
        remainingTtl,
        TimeUnit.MILLISECONDS
    );
}
```

---

## Configuration Checklist

- [ ] `security.jwt.secret` sourced from Kubernetes Secret / Azure Key Vault / AWS Secrets Manager — not `application.yml`
- [ ] Access token TTL ≤ 15 minutes
- [ ] Refresh token rotation enabled
- [ ] Token blacklist (Redis) operational
- [ ] Login endpoint rate-limited and locked out after 5 failures
- [ ] Istio mTLS mode = `STRICT` in all namespaces
- [ ] `RequestAuthentication` applied to API Gateway
- [ ] Passwords stored with BCrypt cost ≥ 12
- [ ] MFA enforced for admin/remediation roles

---

## Testing

```text

| Test Type | Tool | Coverage |
|-----------|------|----------|
| Unit | JUnit + Mockito | `JwtValidationFilter` edge cases |
| Integration | Postman (`tests/postman/`) | Login, refresh, logout flows |
| DAST | OWASP ZAP | Brute-force, token replay |
| Load | Gatling (`tests/performance/`) | Rate-limiter effectiveness under load |

```
---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `security/api-security/JwtValidationFilter.java` | JWT validation servlet filter |
| `security/api-security/rate-limiter-config.yaml` | Rate limiter configuration |
| `istio/security/mtls-strict.yaml` | Enforce mTLS between all services |
| `istio/security/request-authentication.yaml` | External JWT validation via Istio |
| `services/auth-service/application.yml` | Auth-Service runtime config |
```
---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
