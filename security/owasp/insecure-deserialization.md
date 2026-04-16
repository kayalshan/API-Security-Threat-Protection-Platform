# A8 – Insecure Deserialization

## Overview

Insecure deserialization occurs when an application deserializes data supplied by an attacker without sufficient validation. Exploitation can lead to remote code execution (RCE), authentication bypass, privilege escalation, replay attacks, or denial of service. This risk is especially high in Java applications that use Java serialization, applications that pass serialized objects over Kafka, or services that accept serialized objects in HTTP request bodies.

In this platform, deserialization occurs when consuming Kafka messages, processing REST request bodies (JSON via Jackson), and in any component using Java native serialization.

**OWASP Reference:** [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

## Attack Vectors

```text

| Vector | Description | Platform Exposure |
|--------|-------------|-------------------|
| Java Native Serialization | `ObjectInputStream` deserializes gadget chains | Any service using `Serializable` + ObjectInputStream |
| JSON Deserialization (Polymorphic) | Jackson `@JsonTypeInfo` with `id = As.CLASS` enables RCE | API Gateway, Auth-Service, User-Service |
| Kafka Message Deserialization | Malicious message consumed and deserialized | Threat-Detection AI, Remediation-Service consumers |
| HTTP Request Body | Crafted binary payload in request body | Any endpoint accepting `application/octet-stream` |
| Session Cookies | Serialized session object in cookie (e.g., Java serialization) | If using server-side sessions |
```
---

## Prevention Controls

### 1. Avoid Java Native Serialization

Never use `ObjectInputStream` to deserialize data from untrusted sources. Replace with JSON (Jackson), Avro, or Protobuf.

```java
// VULNERABLE — deserializes arbitrary class graph from untrusted input
try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
    MyObject obj = (MyObject) ois.readObject();  // RCE risk if gadgets present
}

// SECURE — use JSON deserialization via Jackson with strict typing
@PostMapping(value = "/events", consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<Void> ingestEvent(@Valid @RequestBody ThreatEventDto event) {
    threatEventService.process(event);
    return ResponseEntity.accepted().build();
}
```

If you absolutely must use `ObjectInputStream`, implement a deserialization filter:

```java
// Java 9+ deserialization filter — allowlist only expected classes
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(info -> {
    if (info.serialClass() == null) return ObjectInputFilter.Status.UNDECIDED;
    String className = info.serialClass().getName();
    if (ALLOWED_CLASSES.contains(className)) return ObjectInputFilter.Status.ALLOWED;
    return ObjectInputFilter.Status.REJECTED;
});
```

### 2. Jackson — Disable Default Typing

Jackson's `FAIL_ON_UNKNOWN_PROPERTIES` and `enableDefaultTyping()` can lead to polymorphic type confusion. Harden Jackson configuration:

```java
@Bean
@Primary
public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();

    // Disable globally-enabled default typing (enables polymorphic RCE)
    // mapper.enableDefaultTyping(...);  <-- NEVER call this

    // Fail on unknown JSON properties to reject unexpected payloads
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    // Do not use ALLOW_COERCION_OF_SCALARS with untrusted input
    mapper.configure(MapperFeature.ALLOW_COERCION_OF_SCALARS, false);

    // Register security module (blocks known dangerous types)
    mapper.registerModule(new JavaTimeModule());

    return mapper;
}
```

If polymorphic deserialization is required, use an explicit allowlist annotation rather than global default typing:

```java
// SAFER — explicit per-class polymorphism with a short, known subtypes list
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = SqlInjectionEvent.class, name = "SQL_INJECTION"),
    @JsonSubTypes.Type(value = XssEvent.class, name = "XSS"),
    @JsonSubTypes.Type(value = BruteForceEvent.class, name = "BRUTE_FORCE")
})
public abstract class ThreatEvent {
    // ...
}
```

### 3. Kafka — Schema Validation and Avro

Use Avro or JSON Schema for Kafka messages instead of Java serialization. Enforce schema validation via a Schema Registry:

```java
// Producer (Threat-Detection AI / Python) — Avro serializer
producer_config = {
    "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
    "schema.registry.url": os.environ["SCHEMA_REGISTRY_URL"],
    "security.protocol": "SASL_SSL",
    # ...
}
producer = AvroProducer(producer_config, default_value_schema=threat_event_schema)
producer.produce(topic="threat-events", value=event_payload)
```

```java
// Consumer (Remediation-Service / Java) — typed Avro deserialization
@KafkaListener(topics = "threat-events", containerFactory = "avroKafkaListenerContainerFactory")
public void consumeThreatEvent(ThreatEventAvro event) {
    // Schema Registry has already validated the message against the registered schema
    remediationService.handle(event);
}
```

Consumer configuration:

```java
@Bean
public ConsumerFactory<String, ThreatEventAvro> avroConsumerFactory() {
    Map<String, Object> props = new HashMap<>();
    props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootstrapServers);
    props.put("schema.registry.url", schemaRegistryUrl);
    props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
    props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, KafkaAvroDeserializer.class);
    props.put(KafkaAvroDeserializerConfig.SPECIFIC_AVRO_READER_CONFIG, true);
    // Only accept schemas from the trusted registry — reject messages with unknown schemas
    return new DefaultKafkaConsumerFactory<>(props);
}
```

### 4. DTO Validation — Validate After Deserialization

Even when using safe deserializers, validate all deserialized objects:

```java
@PostMapping("/threats")
public ResponseEntity<Void> reportThreat(
        @Valid @RequestBody ThreatReportDto report,  // @Valid triggers Bean Validation
        BindingResult result) {
    if (result.hasErrors()) {
        throw new ValidationException("Invalid threat report: " + result.getAllErrors());
    }
    threatService.process(report);
    return ResponseEntity.accepted().build();
}

public class ThreatReportDto {
    @NotBlank
    @Size(max = 50)
    private String threatType;

    @NotBlank
    @Pattern(regexp = "^(LOW|MEDIUM|HIGH|CRITICAL)$")
    private String severity;

    @NotNull
    @PastOrPresent
    private Instant detectedAt;

    @Size(max = 2000)
    private String details;
}
```

### 5. Integrity Signing for Deserialized Data

For high-risk data (e.g., JWT payloads, Kafka event streams used for remediation), verify an HMAC signature before deserialization:

```java
public ThreatEventDto deserializeWithSignatureCheck(byte[] payload, byte[] signature)
        throws GeneralSecurityException {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
    byte[] expectedSig = mac.doFinal(payload);

    if (!MessageDigest.isEqual(expectedSig, signature)) {
        throw new SecurityException("Payload signature validation failed — data may be tampered");
    }
    return objectMapper.readValue(payload, ThreatEventDto.class);
}
```

### 6. Class-Path Gadget Prevention (ysoserial)

Ensure known deserialization gadget libraries are not on the classpath in production:

```xml
<!-- pom.xml — mark dangerous libraries as test-scope only -->
<!-- Never include commons-collections 3.x in production if using ObjectInputStream -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.2</version>
    <scope>test</scope>   <!-- if needed for tests only -->
</dependency>
```

Run `mvn dependency:tree | grep commons-collections` to audit transitive dependencies.

### 7. Restrict Dangerous Content Types

Reject `application/octet-stream` and `application/x-java-serialized-object` at the WAF and API Gateway:

```apache
# security/waf/custom-rules.conf
SecRule REQUEST_HEADERS:Content-Type \
    "@rx application/(x-java-serialized-object|octet-stream|x-serialized)" \
    "id:9020,phase:1,deny,status:415,log,msg:'Potentially serialized object detected in request'"
```

```java
// API Gateway — explicitly reject binary content types
http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
    .addFilterBefore(new ContentTypeRestrictionFilter(
        Set.of("application/x-java-serialized-object", "application/octet-stream")
    ), UsernamePasswordAuthenticationFilter.class);
```

---

## Configuration Checklist

- [ ] No `ObjectInputStream.readObject()` on untrusted data — replaced with JSON/Avro/Protobuf
- [ ] Jackson `enableDefaultTyping()` is NOT called anywhere in the codebase
- [ ] `FAIL_ON_UNKNOWN_PROPERTIES` set to `true` on the shared `ObjectMapper` bean
- [ ] Kafka consumers use Avro + Schema Registry with `SPECIFIC_AVRO_READER_CONFIG=true`
- [ ] All deserialized DTOs pass `@Valid` Bean Validation before processing
- [ ] HMAC integrity check applied to high-risk Kafka event payloads
- [ ] `commons-collections 3.x`, `commons-beanutils`, and similar gadget libraries absent from production classpath
- [ ] WAF rules block `application/x-java-serialized-object` content type
- [ ] Java deserialization filter (`setObjectInputFilter`) set if `ObjectInputStream` is unavoidable

---

## Testing

```text

| Test Type | Tool | Coverage |
|-----------|------|----------|
| SAST | SpotBugs + FindSecBugs (`ObjectDeserialization` detector) | All service source trees |
| Dependency Audit | `mvn dependency:tree` + OWASP Dependency Check | Gadget library detection |
| DAST | ysoserial payloads via OWASP ZAP | All endpoints accepting non-JSON bodies |
| Manual | Burp Suite + ysoserial gadget payloads | Kafka message tampering simulation |
| Unit | JUnit | Jackson config — verify type info rejection, unknown property rejection |
```
---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `security/waf/custom-rules.conf` | WAF rule blocking serialized object content types |
| `messaging/kafka/` | Kafka configuration — migrate to Avro serializers |
| `services/*/pom.xml` | Dependency audit for gadget libraries |
| `ci-cd/github-actions/security-scan.yml` | OWASP Dependency Check in CI |
```
---

## References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Top 10: A08 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [ysoserial — Java deserialization payloads (research reference)](https://github.com/frohoff/ysoserial)
- [Jackson Polymorphic Deserialization and Security](https://github.com/FasterXML/jackson-databind/wiki/Jackson-Release-2.10#changes-default-typing)
