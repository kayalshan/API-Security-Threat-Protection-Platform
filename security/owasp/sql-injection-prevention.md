# A1 – Injection (SQL, NoSQL, OS, LDAP)

## Overview

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Attackers can use injection to manipulate queries, execute unauthorized commands, or access data they are not authorized to view. This platform is exposed to injection risk at every API endpoint that accepts user input and touches a data store or shell command.

**OWASP Reference:** [A01:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

---

## Attack Vectors
```text

| Vector | Description | Platform Exposure |
|--------|-------------|-------------------|
| SQL Injection | Malicious SQL fragments alter a query | User-Service, Auth-Service (JPA/Hibernate) |
| NoSQL Injection | JSON operators (`$where`, `$gt`) manipulate MongoDB queries | Threat-Detection AI data store |
| OS Command Injection | Shell metacharacters passed to `Runtime.exec()` | Remediation-Service automation scripts |
| LDAP Injection | Crafted input manipulates LDAP filters | Auth-Service LDAP integration |
| Expression Language (EL) Injection | Template or EL expressions evaluated at runtime | API Gateway (Spring WebFlux templates) |
```
---

## Prevention Controls

### 1. Parameterized Queries / Prepared Statements

Never concatenate user input directly into a query string.

```java
// VULNERABLE
String query = "SELECT * FROM users WHERE username = '" + username + "'";

// SECURE — JPA named parameter
@Query("SELECT u FROM User u WHERE u.username = :username")
Optional<User> findByUsername(@Param("username") String username);

// SECURE — JDBC PreparedStatement
String sql = "SELECT * FROM users WHERE username = ? AND active = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, username);
stmt.setBoolean(2, true);
ResultSet rs = stmt.executeQuery();
```

### 2. ORM / Repository Layer (Spring Data JPA)

Prefer repository abstractions — they use parameterized queries by default and eliminate raw SQL construction.

```java
// Spring Data repository — safe by default
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsernameAndActiveTrue(String username);
    List<User> findByRoleIn(List<String> roles);
}
```

### 3. Input Validation at API Boundary

Validate all inputs using Bean Validation before they reach the service layer.

```java
public class LoginRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    @Pattern(regexp = "^[a-zA-Z0-9_.-]+$", message = "Username contains invalid characters")
    private String username;

    @NotBlank
    @Size(min = 8, max = 128)
    private String password;
}
```

### 4. Input Sanitization (Platform Helper)

Use `InputSanitization.sanitize()` from `security/api-security/InputSanitization.java` as a defence-in-depth measure alongside parameterized queries.

```java
String safeInput = InputSanitization.sanitize(rawInput);
```

### 5. Least-Privilege Database Accounts

Each service connects with a database account scoped to only the operations it needs.

```text
| Service | Required Privileges |
|---------|---------------------|
| auth-service | SELECT, INSERT on `users`, `sessions` |
| user-service | SELECT, INSERT, UPDATE on `users` |
| threat-detection-ai | SELECT on threat data tables |
| remediation-service | SELECT, UPDATE on `incidents` |
```
---

```sql
-- Example: create a least-privilege user for auth-service
CREATE USER 'auth_svc'@'%' IDENTIFIED BY '<strong-password>';
GRANT SELECT, INSERT ON platform.users TO 'auth_svc'@'%';
GRANT SELECT, INSERT ON platform.sessions TO 'auth_svc'@'%';
FLUSH PRIVILEGES;
```

### 6. WAF Rules (ModSecurity / OWASP CRS)

The platform WAF (`security/waf/modsecurity.conf` and `owasp-crs.conf`) enforces injection detection rules at the ingress layer. Ensure the following rule sets are active:

```apache
# security/waf/owasp-crs.conf — already enabled
SecRuleEngine On
Include /etc/modsecurity/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /etc/modsecurity/crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /etc/modsecurity/crs/REQUEST-933-APPLICATION-ATTACK-PHP.conf
```

### 7. NoSQL Injection (MongoDB) Prevention

```java
// VULNERABLE — string concatenation into a query document
BasicDBObject query = new BasicDBObject("username", "{'$gt': ''}");

// SECURE — typed value binding via Spring Data MongoDB
Query safeQuery = new Query(Criteria.where("username").is(username));
mongoTemplate.findOne(safeQuery, User.class);
```

### 8. OS Command Injection Prevention

Avoid Runtime.exec() with user-supplied values. Use ProcessBuilder with an explicit argument list.

```java
// VULNERABLE
Runtime.getRuntime().exec("ping " + host);

// SECURE
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
pb.redirectErrorStream(true);
Process p = pb.start();
```

---

## Testing

```text

| Test Type | Tool | Target |
|-----------|------|--------|
| SAST | SpotBugs + FindSecBugs | All service source trees |
| DAST | OWASP ZAP (SQLi scanner) | `tests/security/` |
| Integration | Postman (injection test collection) | `tests/postman/` |
| Manual | SQLMap (CI pipeline, `ci-cd/github-actions/security-scan.yml`) | API Gateway endpoints |
```
---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `security/api-security/InputSanitization.java` | Shared sanitization utility |
| `security/waf/owasp-crs.conf` | CRS rule set (SQLi/RCE) |
| `security/waf/modsecurity.conf` | Core ModSecurity engine config |
| `security/waf/custom-rules.conf` | Platform-specific injection rules |
| `ci-cd/github-actions/security-scan.yml` | Automated security scanning in CI |
```
---

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

