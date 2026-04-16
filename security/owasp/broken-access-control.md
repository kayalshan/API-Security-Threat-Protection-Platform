# A5 – Broken Access Control

## Overview

Access control enforces policy so that users cannot act outside of their intended permissions. Broken access control failures allow attackers to access unauthorized functionality and data: viewing other users' accounts, modifying other users' data, performing privileged actions, or accessing APIs without authentication.

In this platform, access control is enforced at three layers: the Istio service mesh (AuthorizationPolicy), the API Gateway (Spring Security / JWT role claims), and individual service business logic. All three layers must be consistent and complete.

**OWASP Reference:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## Attack Vectors
```text
| Vector | Description | Platform Exposure |
|--------|-------------|-------------------|
| IDOR (Insecure Direct Object Reference) | Access resource by guessing/incrementing an ID | User-Service `/users/{id}`, incident endpoints |
| Missing function-level access control | Admin endpoints reachable without admin role | Remediation-Service `/remediate/**` |
| Path traversal | `../` sequences reach unintended files | API Gateway static content serving |
| Elevation of privilege | User modifies their JWT role claim | Auth-Service token validation gap |
| CORS misconfiguration | Wildcard `Access-Control-Allow-Origin` | API Gateway CORS policy |
| Force browsing | Direct URL access to restricted pages | Any service lacking per-route access checks |
| Missing Istio AuthorizationPolicy | Service accessible without role enforcement | Side-car bypassed or policy missing |
```

---

## Prevention Controls

### 1. Istio AuthorizationPolicy — Mesh-Level RBAC

Enforce coarse-grained access control at the mesh layer before traffic even reaches a service pod.


# istio/security/authorization-policy.yaml
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: platform-authz
  namespace: api-security
spec:
  selector:
    matchLabels:
      app: api-gateway
  rules:
    # Public endpoints — no auth required
    - to:
        - operation:
            methods: ["POST"]
            paths: ["/auth/login", "/auth/token/refresh", "/health"]

    # All other requests require a valid JWT
    - from:
        - source:
            requestPrincipals: ["*"]
      to:
        - operation:
            notPaths: ["/auth/login", "/auth/token/refresh", "/health"]
```
---
# Remediation endpoints — only ADMIN role may call

```yaml

apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: remediation-admin-only
  namespace: api-security
spec:
  selector:
    matchLabels:
      app: remediation-service
  rules:
    - from:
        - source:
            requestPrincipals: ["*"]
      to:
        - operation:
            methods: ["POST", "PUT", "DELETE"]
      when:
        - key: request.auth.claims[roles]
          values: ["ADMIN", "SECURITY_ENGINEER"]
```

### 2. Spring Security — Method-Level Authorization

Apply `@PreAuthorize` annotations to enforce fine-grained access control in each service:

```java
// In services/user-service — UserController
@RestController
@RequestMapping("/users")
public class UserController {

    // Any authenticated user may read their own profile
    @GetMapping("/{id}")
    @PreAuthorize("authentication.principal.id == #id or hasRole('ADMIN')")
    public ResponseEntity<UserSummaryDto> getUser(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserSummary(id));
    }

    // Only admins may list all users
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserSummaryDto>> listUsers(Pageable pageable) {
        return ResponseEntity.ok(userService.listUsers(pageable));
    }

    // Only admins may delete users
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

Enable global method security in your Spring Security configuration:

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // ...
}
```

### 3. IDOR Prevention — Ownership Validation

Always verify the requesting user owns the resource, not just that the resource exists:

```java
// VULNERABLE — checks only existence
public UserDetails getUser(Long id) {
    return userRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
}

// SECURE — checks ownership
public UserDetails getUser(Long id, Long requestingUserId) {
    User user = userRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    if (!user.getId().equals(requestingUserId) && !currentUserHasRole("ADMIN")) {
        throw new AccessDeniedException("Access denied");
    }
    return UserDetails.from(user);
}
```

Use UUID primary keys instead of sequential integer IDs to prevent enumeration:

```java
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;   // Non-guessable — harder to enumerate
    // ...
}
```

### 4. JWT Role Claims — Validation

The `JwtValidationFilter` must extract roles from the JWT and populate the Spring Security context. The roles must originate from the auth server — never from user-controlled input:

```java
Claims claims = parseToken(token);
List<String> roles = claims.get("roles", List.class);  // issued by Auth-Service

List<GrantedAuthority> authorities = roles.stream()
    .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
    .collect(Collectors.toList());

SecurityContextHolder.getContext().setAuthentication(
    new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities)
);
```

Role elevation must only happen in the Auth-Service, requiring admin approval — never via a user-facing API.

### 5. CORS Configuration

Restrict `Access-Control-Allow-Origin` to known frontend origins:

```java
// API Gateway — CORS configuration
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(
        "https://dashboard.platform.internal",
        "https://admin.platform.internal"
    ));
    // Do NOT use setAllowedOrigins(List.of("*")) — this allows any origin
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

### 6. Deny by Default — Default-Deny Security Policy

Configure Spring Security to deny all unmatched requests by default:

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/auth/login", "/auth/token/refresh", "/actuator/health").permitAll()
            .requestMatchers("/admin/**", "/remediate/**").hasRole("ADMIN")
            .requestMatchers("/threats/**").hasAnyRole("ADMIN", "ANALYST", "SECURITY_ENGINEER")
            .anyRequest().authenticated()   // default-deny: all other requests need auth
        )
        .addFilterBefore(jwtValidationFilter, UsernamePasswordAuthenticationFilter.class)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable)  // REST API — using JWT, not cookies
        .build();
}
```

### 7. Rate Limiting on Sensitive Operations

Combine access control with rate limiting to prevent bulk enumeration attacks:

```yaml
# security/api-security/rate-limiter-config.yaml
rate-limiter:
  routes:
    - path: /users/**
      requests-per-minute: 60
      burst-capacity: 10
    - path: /incidents/**
      requests-per-minute: 30
      burst-capacity: 5
```

---

## Configuration Checklist

- [ ] Istio `AuthorizationPolicy` applied to every service — default-deny posture
- [ ] `@PreAuthorize` annotations on all controller methods with access requirements
- [ ] Ownership check performed before returning any user-specific resource
- [ ] UUID (non-sequential) primary keys used on all entities accessible via API
- [ ] CORS `allowedOrigins` list contains only known frontend domains (no `*`)
- [ ] Spring Security configured with `anyRequest().authenticated()` as the fallback rule
- [ ] JWT roles sourced exclusively from Auth-Service — not from request parameters
- [ ] Remediation and admin endpoints restricted to `ADMIN` / `SECURITY_ENGINEER` roles

---

## Testing
```text
| Test Type | Tool | Coverage |
|-----------|------|----------|
| Unit | JUnit + Spring Security Test | `@PreAuthorize` — access denied / granted scenarios |
| Integration | Postman (`tests/postman/`) | Cross-user IDOR, role escalation attempts |
| DAST | OWASP ZAP | Forced browsing, privilege escalation scans |
| Manual | Burp Suite — horizontal privilege testing | IDOR for `/users/{id}`, `/incidents/{id}` |

```
---

## Platform Files
```text
| File | Purpose |
|------|---------|
| `istio/security/authorization-policy.yaml` | Mesh-level role-based access policies |
| `istio/security/request-authentication.yaml` | JWT validation at mesh ingress |
| `security/api-security/JwtValidationFilter.java` | JWT → Spring Security context population |
| `security/api-security/rate-limiter-config.yaml` | Rate limits on sensitive endpoints |
| `k8s/base/api-gateway-deployment.yaml` | API Gateway deployment (Spring Security config) |
```
---

## References

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [OWASP Authorization Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
