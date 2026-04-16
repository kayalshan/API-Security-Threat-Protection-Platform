# A9 – Using Components with Known Vulnerabilities

## Overview

Components such as libraries, frameworks, and other software modules run with the same privileges as applications. If a vulnerable component is exploited, an attack can facilitate serious data loss or server takeover. Applications using components with known vulnerabilities can undermine application defenses and enable various attacks with potentially severe impacts.

This platform uses a multi-language, multi-framework architecture (Java/Spring Boot services, Python threat-detection service, Node.js tooling) with dozens of third-party dependencies. Each dependency is a potential attack surface.

**OWASP Reference:** [A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

---

## Platform Technology Stack Inventory

```text

| Component | Location | Version Source |
|-----------|----------|---------------|
| Spring Boot (Java services) | `services/*/pom.xml` | Maven BOM |
| Spring Security | `services/*/pom.xml` | Spring Boot BOM |
| Spring Cloud Gateway | `services/api-gateway/pom.xml` | Spring Cloud BOM |
| Kafka Client (Java) | `services/*/pom.xml` | `kafka-clients` artifact |
| Kafka Client (Python) | `services/threat-detection-ai/requirements.txt` | `confluent-kafka` |
| Jackson Databind | `services/*/pom.xml` | Spring Boot BOM |
| JJWT | `services/auth-service/pom.xml` | Direct dependency |
| Python ML libraries | `services/threat-detection-ai/requirements.txt` | pip |
| Alpine Linux (base images) | `services/*/Dockerfile` | Docker image tag |
| Eclipse Temurin JRE | `services/*/Dockerfile` | Docker image tag |
| Istio | `istio/base/istio-installation.yaml` | Helm chart version |
| ModSecurity + CRS | `security/waf/` | Container image |
```
---

## Prevention Controls

### 1. OWASP Dependency Check — Maven (Java Services)

Add OWASP Dependency Check to every service's `pom.xml`:

```xml
<!-- services/*/pom.xml — in the <build><plugins> section -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.2.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>    <!-- fail build on HIGH/CRITICAL CVEs -->
        <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
        <formats>HTML,JSON</formats>
        <outputDirectory>${project.build.directory}/dependency-check-report</outputDirectory>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

Run manually or in CI:

```bash
mvn org.owasp:dependency-check-maven:check -pl services/api-gateway
mvn org.owasp:dependency-check-maven:check -pl services/auth-service
# ... repeat for each service, or run from the root pom.xml
```

### 2. Python Dependency Audit (Threat-Detection AI)

```bash
# Install safety and audit requirements.txt
pip install safety
safety check -r services/threat-detection-ai/requirements.txt --full-report

# Or use pip-audit (NIST NVD + PyPI Advisory DB)
pip install pip-audit
pip-audit -r services/threat-detection-ai/requirements.txt --output=json \
  --output-file=target/pip-audit-report.json
```

Pin all Python dependencies to exact versions with hashes:

```text
# services/threat-detection-ai/requirements.txt — pin with hashes
confluent-kafka==2.3.0 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab

scikit-learn==1.4.2 \
    --hash=sha256:...
```

### 3. CI Pipeline — Automated Dependency Scanning

```yaml
# ci-cd/github-actions/security-scan.yml — dependency scanning steps
name: Security Scan

on:
  push:
    branches: [main, CodeChanges_kafka_integration]
  pull_request:
  schedule:
    - cron: '0 2 * * 1'   # weekly scan on Mondays at 02:00 UTC

jobs:
  java-dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
      - name: OWASP Dependency Check
        run: mvn --no-transfer-progress org.owasp:dependency-check-maven:check
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: dependency-check-report
          path: '**/target/dependency-check-report/'
        if: always()

  python-dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit -r services/threat-detection-ai/requirements.txt

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
          exit-code: 1
          ignore-unfixed: false
```

### 4. Container Base Image Hardening

Use minimal, updated base images and pin to specific digest SHAs:

```dockerfile
# services/api-gateway/Dockerfile — pin by digest, not just tag
FROM eclipse-temurin:21.0.3_9-jre-alpine@sha256:<digest>

# Regularly rebuild to pick up OS-level patches:
# docker pull eclipse-temurin:21-jre-alpine && docker build .

# Scan built image before deployment
# docker run --rm aquasec/trivy:latest image myrepo/api-gateway:latest
```

Automate image freshness checks in CI:

```yaml
# ci-cd/github-actions/build.yml
- name: Scan Docker image with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myrepo/api-gateway:${{ github.sha }}
    format: sarif
    output: trivy-results.sarif
    severity: HIGH,CRITICAL
    exit-code: 1
```

### 5. Dependency Version Management — Use BOMs

Always manage dependency versions centrally through Bills of Materials (BOMs) rather than individual version declarations:

```xml
<!-- Root pom.xml — centralized BOM import -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>3.3.4</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>2023.0.3</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### 6. Component Inventory and Software Bill of Materials (SBOM)

Generate an SBOM for each service to provide auditable component inventory:

```bash
# Generate CycloneDX SBOM for Java services
mvn org.cyclonedx:cyclonedx-maven-plugin:2.8.0:makeAggregateBom \
    -DoutputFormat=json \
    -DoutputName=sbom

# Generate SBOM for Python service
pip install cyclonedx-bom
cyclonedx-py requirements services/threat-detection-ai/requirements.txt \
    -o services/threat-detection-ai/sbom.json --format json
```

Store SBOMs in the `target/` directory and archive them as build artifacts in CI.

### 7. Istio and Infrastructure Component Updates

Track Istio, Prometheus, Grafana, and ELK versions and apply security patches promptly:

```bash
# Check current Istio version
istioctl version

# Check for available updates
istioctl x precheck
helm repo update && helm search repo istio/istiod --versions | head -10
```

Update procedure:

```bash
# Upgrade Istio control plane (run canary first)
istioctl upgrade --set profile=default \
    --set values.global.proxy.image=proxyv2 \
    --revision=canary

# After validation, promote canary
kubectl label namespace api-security \
    istio.io/rev=canary --overwrite
```

### 8. Suppression Policy for False Positives

Maintain a suppression file to document accepted risk on false-positive CVEs:

```xml
<!-- dependency-check-suppressions.xml -->
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes>False positive — CVE-XXXX-XXXXX applies to a different module within this library.
               Confirmed with vendor advisory. Review date: 2026-03-29.</notes>
        <cve>CVE-2024-XXXXX</cve>
        <packageUrl regex="true">^pkg:maven/org\.example/example-lib@.*$</packageUrl>
    </suppress>
</suppressions>
```

Every suppression must include: CVE ID, justification, reviewer name, and review date. Suppressions expire after 90 days and must be re-reviewed.

---

## Configuration Checklist

- [ ] OWASP Dependency Check plugin in all Java service `pom.xml` files with `failBuildOnCVSS=7`
- [ ] `pip-audit` or `safety` in CI for `services/threat-detection-ai/requirements.txt`
- [ ] Python `requirements.txt` uses exact pinned versions with hashes
- [ ] Trivy container scan in CI for all service Dockerfiles
- [ ] Container base images pinned to digest SHA (not floating `latest` tag)
- [ ] All Java dependency versions managed via Spring Boot BOM
- [ ] SBOM generated per service in CI and archived as build artifact
- [ ] Weekly scheduled vulnerability scan in GitHub Actions
- [ ] Suppression file for false positives with justified, dated, time-limited entries
- [ ] Istio, Prometheus, Grafana, ELK versions tracked and patched within 30 days of CVE disclosure

---

## Testing

```text

| Test Type | Tool | Frequency |
|-----------|------|-----------|
| Java dependency scan | OWASP Dependency Check | Every PR + weekly |
| Python dependency scan | pip-audit | Every PR + weekly |
| Container scan | Trivy | Every image build |
| Transitive dependency audit | `mvn dependency:tree` | On new dependency additions |
| SBOM diff | CycloneDX | On every release |
```
---

## Platform Files

```text

| File | Purpose |
|------|---------|
| `pom.xml` (root) | Parent BOM — centralized version management |
| `services/*/pom.xml` | Service-level dependency declarations |
| `services/threat-detection-ai/requirements.txt` | Python dependency declarations |
| `services/*/Dockerfile` | Base image declarations |
| `ci-cd/github-actions/security-scan.yml` | Dependency scanning in CI |
```
---

## References

- [OWASP Vulnerable Components Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [Trivy Container Scanner](https://aquasecurity.github.io/trivy/)
- [pip-audit](https://pypi.org/project/pip-audit/)
