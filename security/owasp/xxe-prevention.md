# A4 – XML External Entities (XXE)

## Overview

An XML External Entity (XXE) attack exploits misconfigured XML parsers to process external entity references within XML documents. Attackers can use XXE to read arbitrary files from the server filesystem, perform server-side request forgery (SSRF), scan internal networks, or execute remote code when certain conditions are met.

In this platform, XML is consumed by the API Gateway, Auth-Service (SAML responses), and any service that parses XML request bodies or SOAP/XML-based integrations. XXE is also relevant to SVG, DOCX, and RSS files uploaded or fetched by the platform.

**OWASP Reference:** [A05:2021 – Security Misconfiguration (XXE subtype)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## How XXE Works

```xml
<!-- Attacker-supplied XML body -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request>
  <username>&xxe;</username>
</request>
```

When a vulnerable parser processes this, `&xxe;` is replaced with the contents of `/etc/passwd` before the application reads the `username` field.

### Common XXE Variants

```text

| Variant | Technique |
|---------|-----------|
| Classic XXE | `SYSTEM` entity reads local file |
| SSRF via XXE | `SYSTEM "http://169.254.169.254/latest/meta-data/"` — AWS IMDS |
| Blind XXE (OOB) | Entity triggers DNS/HTTP callback; response not returned directly |
| XXE via SVG upload | Malicious SVG processed server-side |
| XXE via SAML | Injected entity in SAML assertion processed by SP |
```
---

## Attack Vectors in This Platform
```text
| Vector | Service | Risk |
|--------|---------|------|
| XML request body parsing | API Gateway, User-Service | Local file disclosure, SSRF |
| SAML assertion processing | Auth-Service (if SAML SSO enabled) | Identity forgery, file disclosure |
| SVG / document upload | User-Service file upload endpoints | Local file disclosure |
| Kafka XML message consumption | Threat-Detection AI, Remediation-Service | Internal SSRF to metadata services |
```
---

## Prevention Controls

### 1. Disable External Entities in All XML Parsers

This is the primary and most reliable control. Apply it to every XML-parsing component.

#### Jackson XML (Spring Boot default for `application/xml`)

```java
// In any @Configuration class or ApiGateway setup
@Bean
public XmlMapper xmlMapper() {
    XmlMapper mapper = new XmlMapper();
    // Disable external DTD and entity declarations
    mapper.configure(FromXmlParser.Feature.EMPTY_ELEMENT_AS_NULL, true);
    XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    return mapper;
}
```

#### JAXB / DocumentBuilder (raw Java XML parsing)

```java
public DocumentBuilder createSafeDocumentBuilder() throws ParserConfigurationException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // Disable all external entity and DTD features
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    return dbf.newDocumentBuilder();
}
```

#### SAX Parser

```java
public SAXParser createSafeSaxParser() throws ParserConfigurationException, SAXException {
    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    return spf.newSAXParser();
}
```

#### StAX (XMLInputFactory)

```java
public XMLInputFactory createSafeXMLInputFactory() {
    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    xif.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    return xif;
}
```

### 2. Prefer JSON Over XML

Where the API contract allows, accept `application/json` exclusively and reject `application/xml` requests at the gateway:

```yaml
# istio/security/authorization-policy.yaml — block XML content-type
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: block-xml-content-type
  namespace: api-security
spec:
  action: DENY
  rules:
    - to:
        - operation:
            methods: ["POST", "PUT", "PATCH"]
      when:
        - key: request.headers[content-type]
          values: ["application/xml", "text/xml", "application/soap+xml"]
```

> **Note:** Only apply this if no service legitimately consumes XML. Remove from the policy any paths that require XML (e.g., SAML callback `/auth/saml/callback`).

### 3. SAML XXE Hardening

If Auth-Service uses SAML (e.g., via `spring-security-saml2-service-provider`), ensure the underlying OpenSAML parser is hardened:

```java
// Auth-Service SAML configuration
@Bean
public OpenSamlAuthenticationProvider samlAuthenticationProvider() {
    // Spring Security 5.6+ uses OpenSAML 4 which disables XXE by default.
    // Verify the version in pom.xml and do NOT downgrade.
    OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
    provider.setAssertionValidator(OpenSamlAuthenticationProvider.createDefaultAssertionValidator());
    return provider;
}
```

Dependency check (`services/auth-service/pom.xml`):

```xml
<!-- Ensure spring-security-saml2-service-provider ≥ 5.6.0 -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-saml2-service-provider</artifactId>
    <!-- version managed by Spring Boot BOM ≥ 2.6.x -->
</dependency>
```

### 4. Input Validation — Content-Type and Schema

Validate XML documents against a strict XSD schema before processing them:

```java
public void validateAgainstSchema(String xmlContent, String schemaPath)
        throws SAXException, IOException {
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    // Disable external schema references
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    Schema schema = factory.newSchema(new File(schemaPath));
    Validator validator = schema.newValidator();
    validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    validator.validate(new StreamSource(new StringReader(xmlContent)));
}
```

### 5. WAF Rule — XXE Detection

ModSecurity CRS includes XXE detection rules. Confirm they are active:

```apache
# security/waf/owasp-crs.conf
Include /etc/modsecurity/crs/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
# Also covers XXE patterns in REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /etc/modsecurity/crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
```

Custom rule to block DOCTYPE declarations:

```apache
# security/waf/custom-rules.conf
SecRule REQUEST_BODY "@rx (?i)<\s*!DOCTYPE[^>]*>" \
    "id:9001,phase:2,deny,status:400,log,msg:'XXE attempt: DOCTYPE declaration detected'"
SecRule REQUEST_BODY "@rx (?i)ENTITY\s+\w+\s+SYSTEM" \
    "id:9002,phase:2,deny,status:400,log,msg:'XXE attempt: SYSTEM entity declaration detected'"
```

### 6. Restrict Outbound Network Access (SSRF Mitigation)

Prevent XXE-based SSRF from reaching internal metadata services by applying Istio egress control:

```yaml
# istio — ServiceEntry to allow only approved external destinations
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: approved-external-apis
  namespace: api-security
spec:
  hosts:
    - "api.approved-partner.com"
  ports:
    - number: 443
      name: https
      protocol: HTTPS
  resolution: DNS
  location: MESH_EXTERNAL
```

With `outboundTrafficPolicy: REGISTRY_ONLY` in the mesh config, all other external calls (including `169.254.169.254`) are blocked.

---

## Configuration Checklist

- [ ] `disallow-doctype-decl` set to `true` on all `DocumentBuilderFactory` instances
- [ ] `IS_SUPPORTING_EXTERNAL_ENTITIES` set to `false` on all `XMLInputFactory` instances
- [ ] `XMLConstants.ACCESS_EXTERNAL_DTD` set to `""` on all `SchemaFactory` / `Validator` instances
- [ ] SAML library ≥ Spring Security 5.6 (OpenSAML 4)
- [ ] XML schema validation applied before processing XML input
- [ ] WAF CRS rule sets including Java attack rules loaded and in enforce mode
- [ ] Custom WAF rules blocking `DOCTYPE` and `SYSTEM` patterns
- [ ] Istio egress policy restricts outbound HTTP to approved endpoints only

---

## Testing

| Test Type | Tool | Coverage |
|-----------|------|----------|
| SAST | SpotBugs + FindSecBugs | Unsafe XML parser instantiation |
| DAST | OWASP ZAP (XXE active scanner) | `tests/security/` |
| Manual | Burp Suite XXE extension | SAML, file upload, XML body endpoints |
| Unit | JUnit | `createSafeDocumentBuilder()` — attempt to parse DOCTYPE should throw |

---

## Platform Files

| File | Purpose |
|------|---------|
| `security/waf/custom-rules.conf` | WAF rules blocking DOCTYPE/SYSTEM entity patterns |
| `security/waf/owasp-crs.conf` | CRS Java attack rules (includes XXE) |
| `istio/security/authorization-policy.yaml` | Block XML content-type at mesh level |
| `services/auth-service/pom.xml` | SAML library version control |

---

## References

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: A04 XXE (2017)](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE))
- [OWASP XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)
