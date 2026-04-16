# A7 – Cross-Site Scripting (XSS)

## Overview

Cross-Site Scripting (XSS) flaws occur when an application includes unvalidated, unescaped user data in a new web page. Attackers can execute scripts in the victim's browser, allowing session hijacking, credential theft, page defacement, redirection to malicious sites, or keylogging. XSS is relevant to any service in this platform that generates HTML responses or reflects user-supplied values into API responses consumed by browser-based clients.

**OWASP Reference:** [A03:2021 – Injection (XSS subtype)](https://owasp.org/Top10/A03_2021-Injection/)

---

## XSS Types
```text

| Type | How It Works | Platform Exposure |
|------|-------------|-------------------|
| Reflected XSS | Malicious script in request is immediately reflected in response | API Gateway error pages, search endpoints |
| Stored XSS | Malicious script saved to database and served to other users | User-Service profile fields, incident notes |
| DOM-Based XSS | Client-side script uses attacker-controlled source to write to DOM | Dashboard frontend JavaScript |
| Blind XSS | Payload executes in an internal admin view | Kibana dashboards, admin panels |
```
---

## Prevention Controls

### 1. Output Encoding — Never Trust User Data in Output

Encode all user-controlled values before inserting them into an HTML context.

```java
// security/api-security/InputSanitization.java — enhanced
import org.owasp.encoder.Encode;

public class InputSanitization {

    // HTML context — for values inserted into HTML element content
    public static String forHtml(String input) {
        if (input == null) return "";
        return Encode.forHtml(input);
    }

    // HTML attribute context — for values inside HTML attribute values
    public static String forHtmlAttribute(String input) {
        if (input == null) return "";
        return Encode.forHtmlAttribute(input);
    }

    // JavaScript context — for values inside JS strings
    public static String forJavaScript(String input) {
        if (input == null) return "''";
        return Encode.forJavaScript(input);
    }

    // URL context — for values used in href/src attributes
    public static String forUri(String input) {
        if (input == null) return "";
        return Encode.forUri(input);
    }

    // Legacy: strip script tags (insufficient alone — use Encode.forHtml instead)
    @Deprecated
    public static String sanitize(String input) {
        return input == null ? "" : input.replaceAll("<script.*?>.*?</script>", "");
    }
}
```

Add the OWASP Java Encoder dependency (`services/*/pom.xml`):

```xml
<dependency>
    <groupId>org.owasp.encoder</groupId>
    <artifactId>encoder</artifactId>
    <version>1.2.3</version>
</dependency>
```

### 2. Server-Side Template Engines — Auto-Escaping

If any service renders server-side HTML, use a template engine that auto-escapes by default:

```html
<!-- Thymeleaf — safe: th:text auto-escapes -->
<p th:text="${user.displayName}">DisplayName</p>

<!-- UNSAFE — th:utext renders raw HTML; never use with user input -->
<p th:utext="${user.displayName}">DisplayName</p>
```

### 3. Content Security Policy (CSP)

Set a strict CSP header on all API responses to limit what scripts the browser will execute:

```java
// API Gateway — add to security headers filter (see A6 security-misconfiguration.md)
.contentSecurityPolicy(csp -> csp.policyDirectives(
    "default-src 'none'; " +
    "script-src 'self'; " +                    // no inline scripts, no CDN
    "style-src 'self' 'nonce-{NONCE}'; " +     // nonce for inline styles if needed
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self' https://api.platform.internal; " +
    "frame-ancestors 'none'; " +               // prevent clickjacking
    "form-action 'self'; " +
    "base-uri 'self'; " +
    "object-src 'none'"
))
```

For responses containing nonces (server-side rendering):

```java
// Generate a per-request nonce
String nonce = Base64.getEncoder().encodeToString(
    SecureRandom.getInstanceStrong().generateSeed(16)
);
request.setAttribute("cspNonce", nonce);
response.setHeader("Content-Security-Policy",
    "script-src 'nonce-" + nonce + "' 'strict-dynamic'");
```

### 4. Input Validation — Reject Malicious Patterns at the Boundary

Validate inputs against an allowlist before processing. Use Bean Validation for structured fields:

```java
public class UserProfileUpdateRequest {

    @NotBlank
    @Size(max = 100)
    @Pattern(regexp = "^[\\p{L}\\p{N} '.,\\-]+$",
             message = "Display name contains invalid characters")
    private String displayName;

    @NotBlank
    @Email
    private String email;

    @Size(max = 500)
    private String bio;  // free-text — must be output-encoded when displayed
}
```

### 5. WAF Rules — XSS Detection

Verify the OWASP CRS XSS rules are active in `security/waf/owasp-crs.conf`:

```apache
# security/waf/owasp-crs.conf
Include /etc/modsecurity/crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf
```

Custom rules for platform-specific patterns:

```apache
# security/waf/custom-rules.conf — XSS patterns
SecRule ARGS "@rx (?i)(<script|javascript:|vbscript:|on\w+=|<iframe|<object|<embed)" \
    "id:9010,phase:2,deny,status:400,log,msg:'XSS pattern detected in request'"
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(<script|javascript:)" \
    "id:9011,phase:1,deny,status:400,log,msg:'XSS pattern detected in User-Agent'"
```

### 6. JSON API — Set `X-Content-Type-Options` and Avoid HTML in JSON

For REST JSON APIs, ensure the browser cannot interpret responses as HTML:

```java
// All JSON API responses must carry:
response.setContentType("application/json; charset=UTF-8");
response.setHeader("X-Content-Type-Options", "nosniff");
```

Never embed user-controlled HTML strings inside JSON properties that are subsequently rendered by a frontend via `innerHTML`.

### 7. HttpOnly and Secure Cookie Flags

If session cookies are used (alongside or instead of JWTs for web sessions):

```java
// API Gateway — cookie configuration
ResponseCookie cookie = ResponseCookie.from("session", sessionToken)
    .httpOnly(true)      // not accessible via JavaScript
    .secure(true)        // transmitted only over HTTPS
    .sameSite("Strict")  // prevent CSRF-driven XSS
    .path("/")
    .maxAge(Duration.ofMinutes(15))
    .build();
response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

### 8. Sanitize Rich-Text Input (HTML Allowlist)

If the platform accepts rich-text (e.g., incident description with formatting), sanitize with an allowlist:

```java
// Use OWASP Java HTML Sanitizer
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class HtmlSanitizer {
    private static final PolicyFactory POLICY =
        Sanitizers.FORMATTING          // bold, italic, etc.
        .and(Sanitizers.BLOCKS)        // p, div, blockquote
        .and(Sanitizers.LINKS);        // <a href> — sanitized

    public static String sanitizeHtml(String untrustedHtml) {
        return POLICY.sanitize(untrustedHtml);
    }
}
```

Dependency (`services/*/pom.xml`):

```xml
<dependency>
    <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
    <artifactId>owasp-java-html-sanitizer</artifactId>
    <version>20220608.1</version>
</dependency>
```

---

## Anti-Patterns to Avoid

```java
// UNSAFE — string concatenation into HTML
String html = "<div>" + userInput + "</div>";

// UNSAFE — raw HTML in JSON field rendered via innerHTML
{ "message": "<script>steal(document.cookie)</script>" }

// UNSAFE — th:utext with user data in Thymeleaf
// <p th:utext="${user.bio}">

// UNSAFE — stripping only <script> tags (bypassable)
input.replaceAll("<script.*?>.*?</script>", "");  // bypassed by <SCRIPT>, <img onload=...>
```

---

## Configuration Checklist

- [ ] OWASP Java Encoder used for all output encoding (not manual replace)
- [ ] Thymeleaf / template engine auto-escaping confirmed active (`th:text`, not `th:utext`)
- [ ] CSP header set with `default-src 'none'` and specific allow-list per resource type
- [ ] `X-Content-Type-Options: nosniff` on all responses
- [ ] `frame-ancestors 'none'` in CSP (prevents clickjacking)
- [ ] Session cookies marked `HttpOnly`, `Secure`, `SameSite=Strict`
- [ ] WAF CRS XSS rules (REQUEST-941) active in ENFORCE mode
- [ ] Custom WAF rules for `<script>` / `javascript:` / `on*=` patterns
- [ ] Rich-text input processed through OWASP HTML Sanitizer allowlist policy

---

## Testing
```text

| Test Type | Tool | Coverage |
|-----------|------|----------|
| SAST | SpotBugs + FindSecBugs | Unsafe output patterns |
| DAST | OWASP ZAP (active XSS scanner) | All API endpoints |
| Manual | Burp Suite XSS probe | Stored XSS in profile/incident fields |
| CSP Validation | [CSP Evaluator](https://csp-evaluator.withgoogle.com/) | CSP header policy review |
| Integration | Postman (`tests/postman/`) | XSS payloads in all free-text fields |
```
---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `security/api-security/InputSanitization.java` | Output encoding utilities |
| `security/waf/custom-rules.conf` | Custom WAF XSS detection rules |
| `security/waf/owasp-crs.conf` | CRS XSS rule set (REQUEST-941) |
| `security/api-security/rate-limiter-config.yaml` | Rate limit to slow XSS probing |
| `ci-cd/github-actions/security-scan.yml` | DAST in CI pipeline |
```
---

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)

