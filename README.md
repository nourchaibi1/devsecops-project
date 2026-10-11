# DevSecOps Security Pipeline

A Spring Boot Timesheet application protected by a multi-stage DevSecOps pipeline and deployed to a local Kubernetes cluster using Minikube.

The project integrates security across five DevSecOps phases:

```text
PRE-COMMIT → COMMIT → ACCEPTANCE → PRODUCTION → OPERATIONS
```

Jenkins orchestrates the pipeline, while specialized security controls perform secret detection, automated testing, static analysis, dependency assessment, Infrastructure as Code scanning, container scanning, dynamic application testing, Kubernetes security validation, runtime secret injection, threat detection, continuous scanning, and monitoring.

---

## Project Overview

This project demonstrates how security can be integrated throughout the software delivery lifecycle instead of being performed only at the end of development.

The pipeline combines:

- Preventive security controls
- Automated security testing
- Vulnerability detection
- Policy enforcement
- Runtime secret management
- Runtime threat detection
- Continuous workload assessment
- Infrastructure monitoring
- Automated evidence collection

By exploring this repository, the reader will understand:

- How secrets are detected before entering Git history
- How source code is analyzed using SAST
- How third-party dependencies are evaluated for known vulnerabilities
- How Kubernetes manifests are assessed before deployment
- How container images are scanned and linked to Jenkins build numbers
- How a Software Bill of Materials supports supply-chain visibility
- How the deployed application is tested using DAST
- How Kyverno policies control Kubernetes workloads
- How Network Policies restrict communication between services
- How HashiCorp Vault injects database credentials at runtime
- How Kubescape evaluates Kubernetes security posture
- How Lynis audits the production host’s hardening posture
- How Falco detects suspicious container behavior
- How Trivy Operator continuously assesses deployed workloads
- How Prometheus and Grafana provide operational visibility
- How Jenkins consolidates evidence into a DevSecOps report

---

## Table of Contents

- [Security Results](#security-results)
- [Five DevSecOps Security Phases](#five-devsecops-security-phases)
- [Pipeline Stages Overview](#pipeline-stages-overview)
- [1. Pre-commit Phase](#1-pre-commit-phase)
- [2. Commit Phase](#2-commit-phase)
- [3. Acceptance Phase](#3-acceptance-phase)
- [4. Production Phase](#4-production-phase)
- [5. Operations Phase](#5-operations-phase)
- [Secrets Management](#secrets-management)
- [Security Gates](#security-gates)
- [Automated Security Reporting](#automated-security-reporting)
- [Security Toolchain](#security-toolchain)
- [Supporting Platform](#supporting-platform)
- [Repository Structure](#repository-structure)
- [Security Notice](#security-notice)
---

## Security Results

| Security Area | Before | After | Security Outcome |
|---|---:|---:|---|
| Dependency vulnerabilities | 84 | 7 | Critical findings reduced from 5 to 0 |
| Container vulnerabilities | 26 | 7 | Critical findings reduced from 2 to 0 |
| OWASP ZAP | Not initially measured | 64 checks passed | 0 failures and 3 warnings |
| SonarQube Quality Gate | Not initially enforced | Passed | Required security and quality conditions satisfied |
| Unit and security tests | Not automated | 11/11 passed | Automated regression validation |
| Runtime secret management | Kubernetes Secret | Vault injection | Database credentials injected at runtime |

Build-specific results are published through the Jenkins DevSecOps report and archived with the pipeline evidence.

---

## Five DevSecOps Security Phases

| DevSecOps Phase | Implemented Tools | Security Activities |
|---|---|---|
| **Pre-Commit** | pre-commit, Gitleaks | Detects passwords, tokens, private keys, database credentials, and other sensitive data before they enter Git history. |
| **Commit** | Jenkins, JUnit, JaCoCo, SonarQube, SonarQube Quality Gate, Trivy, OWASP Dependency Check, CycloneDX | Performs automated testing, coverage analysis, SAST, dependency scanning, IaC scanning, container scanning, Quality Gate validation, and SBOM generation. |
| **Acceptance** | Application health checks, OWASP ZAP, Gauntlt | Confirms application availability and performs dynamic web-security testing and repeatable attack scenarios. |
| **Production** | Kyverno, Kubernetes Network Policies, Kubescape, HashiCorp Vault Agent Injector, Lynis | Enforces Kubernetes policies, restricts network communication, assesses cluster posture, injects runtime secrets, and audits host-hardening configuration. |
| **Operations** | Falco, Trivy Operator, Prometheus, Grafana, Jenkins reporting and email notifications | Detects runtime threats, continuously scans workloads, monitors application and cluster health, visualizes findings, and publishes security evidence. |

---

## Pipeline Stages Overview

The Jenkins pipeline contains 27 stages covering build validation, security testing, deployment, production protection, runtime detection, monitoring, and reporting.

### 1. Tool Version and Vulnerability Check

Identifies the installed versions of Trivy, Kubescape, Lynis, and OWASP ZAP.

Where an appropriate product identifier is available, the stage queries the NVD to identify publicly reported vulnerabilities affecting the installed tool version.

### 2. Checkout from GitHub

Retrieves the selected branch and cleans the Jenkins workspace.

This prevents stale files, previous artifacts, and old scan results from affecting the current build.

### 3. Secret Security Scan

Uses pre-commit and Gitleaks to detect credentials, tokens, private keys, and other sensitive values before compilation.

### 4. Clean Project

Removes files generated by previous Maven builds to provide a clean and reproducible workspace.

### 5. Build Artifact

Compiles and packages the Spring Boot application into an executable JAR.

Tests are executed separately in the following stage.

### 6. Unit and Security Tests

Executes the JUnit test suite and generates a JaCoCo coverage report.

Failed tests block the pipeline.

### 7. SAST with SonarQube

Analyzes source code for vulnerabilities, security hotspots, reliability issues, maintainability problems, duplicated code, and test coverage.

### 8. SonarQube Quality Gate

Waits for the SonarQube Quality Gate result.

The pipeline stops if the configured security and quality requirements are not satisfied.

### 9. Dependency Security Scan

Uses Trivy Software Composition Analysis to detect known HIGH and CRITICAL vulnerabilities in project dependencies.

### 10. Infrastructure as Code Scan

Uses Trivy to inspect Kubernetes manifests and configuration files for insecure deployment settings.

### 11. Publish and Archive Artifact

Archives the generated JAR in Jenkins to preserve a traceable application artifact.

### 12. Build Container Image

buildes the application image and tags it using the Jenkins build number.

### 13. Trivy Image Scan and SBOM

Scans the final image for fixable HIGH and CRITICAL vulnerabilities and generates a CycloneDX SBOM.

### 14. Push to Docker Hub

Uses Jenkins Credentials to authenticate with Docker Hub and publish the scanned image.

### 15. Deploy to Kubernetes

Updates the Timesheet deployment with the new image.

If rollout fails, Jenkins collects diagnostics and attempts an automatic rollback.

### 16. Application Health Check

Verifies:

- Kubernetes rollout completion
- Application availability
- Spring Boot health
- Prometheus health

### 17. Kyverno Policy Verification

Confirms that the Kyverno controllers are available and that the required policies are present, ready, and configured with the expected enforcement modes.

### 18. Kubernetes Network Policy Verification

Confirms that the required ingress and egress Network Policies are deployed in the `chap4` namespace.

### 19. Vault Secrets Management Verification

Verifies:

- Vault Agent Injector availability
- Mutation webhook availability
- Timesheet Vault annotations
- Vault role
- Dedicated Kubernetes service account
- Injected init container
- Injected sidecar
- Generated secret file

Secret values are never displayed.

### 20. Kubescape Security Assessment

Evaluates deployed Kubernetes resources against NSA Kubernetes hardening guidance and MITRE-aligned controls.

### 21. Lynis Host-Hardening Audit

Assesses the host supporting Jenkins and the local production-like environment.

It generates a hardening index and security recommendations.

### 22. OWASP ZAP DAST

Performs dynamic application security testing against the deployed application and generates HTML and JSON reports.

### 23. Gauntlt Security Tests

Executes repeatable attack definitions to validate project-specific security requirements.

### 24. Falco Runtime Detection

Performs controlled suspicious actions and verifies that Falco detects the resulting runtime behavior.

### 25. Trivy Operator Continuous Scanning

Collects vulnerability, configuration-audit, and exposed-secret reports for deployed Kubernetes workloads.

### 26. Prometheus and Grafana Monitoring

Verifies Prometheus readiness, target health, active alerts, monitoring rules, and Grafana availability.

### 27. Email Notification

Generates the latest DevSecOps summary and sends the result, report link, and security-report attachments by email.

### Pipeline Execution Flow

```text
TOOL CHECK
    ↓
CHECKOUT
    ↓
SECRET SCAN
    ↓
CLEAN AND BUILD
    ↓
UNIT TESTS AND COVERAGE
    ↓
SONARQUBE SAST
    ↓
QUALITY GATE
    ↓
DEPENDENCY AND IaC SCANNING
    ↓
ARCHIVE APPLICATION ARTIFACT
    ↓
BUILD CONTAINER IMAGE
    ↓
IMAGE SCAN AND SBOM
    ↓
PUSH TO DOCKER HUB
    ↓
DEPLOY TO KUBERNETES
    ↓
APPLICATION HEALTH CHECK
    ↓
KYVERNO POLICY VERIFICATION
    ↓
NETWORK POLICY VERIFICATION
    ↓
VAULT INJECTION VERIFICATION
    ↓
KUBESCAPE ASSESSMENT
    ↓
LYNIS HOST AUDIT
    ↓
OWASP ZAP DAST
    ↓
GAUNTLT SECURITY TESTS
    ↓
FALCO RUNTIME VALIDATION
    ↓
TRIVY OPERATOR SCANNING
    ↓
PROMETHEUS AND GRAFANA MONITORING
    ↓
REPORTING AND EMAIL NOTIFICATION
```

---

## 1. Pre-Commit Phase

The Pre-Commit phase prevents credentials and sensitive values from entering Git history.

### pre-commit Framework

The pre-commit framework provides a repeatable mechanism for executing repository checks before code progresses through the delivery workflow.

### Gitleaks

Gitleaks scans project files for patterns associated with:

- Passwords
- API tokens
- Private keys
- Docker registry credentials
- SonarQube tokens
- Vault tokens
- Database credentials
- Other hardcoded secrets

The control is blocking. If sensitive content is detected, Jenkins stops the pipeline.

### Security Objective

Deleting a secret from the latest version of a file does not necessarily remove it from Git history.

Early detection reduces the risk of credentials being published, cached, copied, or exposed through repository history.

---

## 2. Commit Phase

The Commit phase performs the main automated security assessments after code is pushed to GitHub.

### JUnit Tests

JUnit validates application behavior and detects:

- Broken business logic
- Incorrect validation
- Unexpected service behavior
- Unhandled error conditions
- Regressions introduced by code changes

Failed tests block the pipeline.

### JaCoCo Coverage

JaCoCo measures which classes and methods are exercised by the automated tests.

Coverage identifies logic that may not be adequately tested. It is treated as an assurance metric and not as proof that the application is vulnerability-free.

### SonarQube SAST

SonarQube analyzes source code without executing the application.

It reports:

- Security vulnerabilities
- Security hotspots
- Reliability issues
- Maintainability issues
- Duplicated code
- Potentially unsafe coding patterns
- Test coverage

Security hotspots identify security-sensitive code requiring manual review, even when the issue is not automatically classified as a confirmed vulnerability.

### SonarQube Quality Gate

The Quality Gate evaluates the application against configured security and quality conditions.

This is a blocking control. An unacceptable result prevents image buid and deployment.

### Trivy Dependency Scanning

Trivy scans project dependencies for known vulnerabilities, with emphasis on HIGH and CRITICAL findings.

This identifies vulnerabilities introduced by third-party software components.

### OWASP Dependency Check

OWASP Dependency Check provides an additional dependency assessment and supports comparison with Trivy.

Verified dependency remediation:

- Findings reduced from **84 to 7**
- Critical findings reduced from **5 to 0**

### Trivy Infrastructure as Code Scanning

Trivy analyzes Kubernetes manifests and configuration files for weaknesses such as:

- Privileged workloads
- Missing security contexts
- Missing resource restrictions
- Excessive permissions
- Unsafe Kubernetes configuration

### Trivy Container Image Scanning

Trivy scans the final image for vulnerable operating-system packages and application dependencies.

Verified container remediation:

- Findings reduced from **26 to 7**
- Critical findings reduced from **2 to 0**

Each image is tagged using the Jenkins build number:

```text
nourchaibi/timesheet:<BUILD_NUMBER>
```

This provides traceability between the Jenkins execution, scan results, registry image, Kubernetes deployment, and Trivy Operator report.

### CycloneDX SBOM

A CycloneDX Software Bill of Materials records the software components contained in the final image.

The SBOM supports:

- Component inventory
- Software supply-chain visibility
- Vulnerability investigation
- Build traceability
- Incident response

The SBOM is an inventory artifact, not a vulnerability scanner.

---

## 3. Acceptance Phase

The Acceptance phase evaluates the complete running application before it is accepted.

### Application Health Validation

Jenkins verifies:

- Kubernetes rollout completion
- Pod availability
- Application reachability
- Spring Boot health
- Prometheus availability

Security testing only begins after the application is confirmed operational.

### OWASP ZAP

OWASP ZAP performs dynamic application security testing against the running web application.

The baseline scan evaluates:

- Missing security headers
- Information disclosure
- Cookie security attributes
- Web-server weaknesses
- Suspicious HTTP behavior
- Client-side security configuration

Validated results:

- **64 checks passed**
- **0 failures**
- **3 warnings**

The ZAP stage is non-blocking so Jenkins can continue collecting runtime and operational evidence.

### Gauntlt

Gauntlt executes repeatable attack definitions against the deployed application.

It complements ZAP:

- **OWASP ZAP** performs broad web-security assessment.
- **Gauntlt** validates application-specific attack scenarios and security expectations.

---

## 4. Production Phase

The Production phase protects and evaluates the Kubernetes environment and its supporting host.

### Controlled Rollout and Rollback

Jenkins waits for the deployment rollout to complete successfully.

If rollout fails, Jenkins collects:

- Pod status
- Deployment details
- Application logs
- Kubernetes events

Jenkins then attempts to restore the previous deployment revision.

### Kyverno Policy as Code

Kyverno enforces or audits Kubernetes security requirements.

| Policy | Mode | Security Purpose |
|---|---|---|
| `disallow-privileged` | Enforce | Blocks privileged containers |
| `disallow-root-user` | Audit | Detects containers configured to run as root |
| `require-resource-limits` | Audit | Detects workloads without CPU or memory limits |

The pipeline verifies:

- Admission controller availability
- Background controller availability
- Cleanup controller availability
- Reports controller availability
- Required policy presence
- Policy readiness
- Enforcement mode

The privileged-container policy blocks non-compliant workloads. Audit policies preserve visibility without immediately rejecting existing workloads.

### Kubernetes Network Policies

Network Policies restrict communication between workloads.

| Policy | Security Effect |
|---|---|
| `allow-timesheet-to-mysql` | Allows the approved application-to-database connection |
| `default-deny-ingress` | Blocks inbound traffic unless explicitly permitted |
| `deny-mysql-egress` | Prevents unauthorized outbound connections from MySQL |

These policies reduce:

- Lateral movement
- Unauthorized communication
- Unintended service exposure
- Database-initiated outbound connections

### Kubescape

Kubescape assesses deployed Kubernetes resources against:

- NSA Kubernetes Hardening Guidance
- MITRE-aligned controls

Kyverno and Kubescape provide complementary functions:

- **Kyverno** enforces or audits admission policies.
- **Kubescape** evaluates the security posture of deployed resources.

### HashiCorp Vault Agent Injector

Vault injects database credentials into Timesheet pods at runtime.

The application uses:

```text
Kubernetes service account: timesheet-vault
Vault role: timesheet
Injected file: /vault/secrets/application-vault.properties
```

Vault Agent Injector introduces:

- A `vault-agent-init` init container
- A `vault-agent` sidecar
- A shared in-memory secret volume
- A generated Spring Boot properties file

The pipeline verifies the injection without displaying secret values.

### Lynis Host-Hardening Audit

Lynis audits the host supporting Jenkins and the local production-like deployment environment.

The assessment covers:

- Authentication configuration
- File and directory permissions
- Logging and auditing
- Installed services
- Network configuration
- Kernel and operating-system settings
- Security-tool configuration

Lynis generates a hardening index and recommendations for manual review.

It belongs to the Production phase because it evaluates the security configuration of the host supporting the deployed environment.

The control is non-blocking because some recommendations require manual infrastructure changes or risk-based decisions.

---

## 5. Operations Phase

The Operations phase continuously observes and evaluates the running environment.

### Falco

Falco detects suspicious container and Kubernetes activity.

| Detection | Security Risk |
|---|---|
| Shell execution inside a container | Unexpected command execution |
| Sensitive file access | Credential or system-data discovery |
| Private-key discovery | Credential theft preparation |
| New binary execution | Possible payload execution |
| Kubernetes API access | Cluster discovery or unauthorized control |

The pipeline performs controlled actions and collects the corresponding Falco evidence.

Falco is a detective control. It complements preventive controls such as Kyverno, Network Policies, and secure workload configuration.

### Trivy Operator

Trivy Operator continuously assesses Kubernetes workloads after deployment.

It produces:

- Vulnerability reports
- Configuration audit reports
- Exposed-secret reports
- Workload-specific findings

The pre-deployment image scan evaluates the container before release, while Trivy Operator continues assessing the deployed workload.

### Prometheus

Prometheus collects application, Kubernetes, and infrastructure metrics.

The pipeline verifies:

- Prometheus readiness
- Target availability
- Active alerts
- Monitoring rules
- Scrape health

Prometheus is an observability platform. Its security value comes from detecting unavailable services, failed targets, abnormal behavior, and operational conditions associated with incidents.

### Grafana

Grafana visualizes operational and security information, including:

- Falco runtime events
- Kyverno policy results
- Application health
- Kubernetes state
- Prometheus alerts
- OWASP ZAP findings
- Security trends

Grafana is a visualization platform rather than a vulnerability scanner. It centralizes findings produced by the security and monitoring controls.

### Jenkins Reporting and Notifications

Jenkins consolidates findings from the pipeline and publishes them through:

- HTML security reports
- Archived build artifacts
- Build descriptions
- Console output
- Email notifications

This provides traceability between each build, image, deployment, scan result, and report.

---

## Secrets Management

The project separates CI/CD credentials from application runtime secrets.

### Jenkins Credentials

Jenkins Credentials protects:

- SonarQube token
- Docker Hub token

These credentials are injected only into the stages that require them and are not stored directly in the Jenkinsfile.

### HashiCorp Vault

Vault protects the application database credentials.

Timesheet authenticates using:

- A dedicated Kubernetes service account
- A restricted Vault role
- A least-privilege Vault policy

The credentials are rendered into an in-memory file consumed by Spring Boot.

Secret values are never printed in Jenkins logs or archived reports.

### Separation of Responsibilities

- **Gitleaks** detects accidentally committed secrets.
- **Jenkins Credentials** protects CI/CD authentication values.
- **Vault** supplies application secrets at runtime.

---

## Security Gates

### Blocking Controls

The following failures stop the pipeline:

- Gitleaks secret detection
- Application compilation
- Unit and security tests
- SonarQube analysis
- SonarQube Quality Gate
- Container image neation
- Docker Hub publication
- Kubernetes deployment
- Application health validation

### Configurable Container Gate

The Trivy image scan supports:

- **Report mode:** Findings are documented without blocking deployment.
- **Enforcement mode:** Matching fixable HIGH or CRITICAL findings stop deployment.

### Non-Blocking Controls

The following controls report risks and may mark the pipeline unstable:

- Trivy dependency scan
- Trivy IaC scan
- Kyverno verification
- Network Policy verification
- Vault injection verification
- Kubescape
- Lynis
- OWASP ZAP
- Gauntlt
- Falco
- Trivy Operator
- Prometheus and Grafana verification

This design allows Jenkins to collect complete security evidence even when a non-critical control reports a risk.

---

## Automated Security Reporting

Jenkins generates a consolidated DevSecOps report containing:

- Pipeline stage status and duration
- Unit-test results
- Code coverage
- SonarQube findings
- Quality Gate status
- Dependency vulnerabilities
- Infrastructure as Code findings
- Container vulnerabilities
- SBOM evidence
- Kyverno policy status
- Network Policy status
- Vault injection status
- Kubescape findings
- Lynis hardening score
- OWASP ZAP findings
- Gauntlt results
- Falco events
- Trivy Operator findings
- Prometheus target health
- Grafana health

The report is:

- Published through Jenkins
- Archived with build artifacts
- Used in the build description
- Included in the pipeline email notification

---

## Security Toolchain

| Security Function | Tool |
|---|---|
| Secret detection | Gitleaks |
| Automated test assurance | JUnit and JaCoCo |
| Static application security testing | SonarQube |
| Security and quality gate | SonarQube Quality Gate |
| Dependency vulnerability assessment | Trivy and OWASP Dependency Check |
| Infrastructure as Code scanning | Trivy |
| Container vulnerability scanning | Trivy |
| Software component inventory | CycloneDX SBOM |
| Dynamic application security testing | OWASP ZAP |
| Automated attack scenarios | Gauntlt |
| Policy as Code | Kyverno |
| Network segmentation | Kubernetes Network Policies |
| Kubernetes posture assessment | Kubescape |
| Runtime secrets management | HashiCorp Vault |
| Host-hardening assessment | Lynis |
| Runtime threat detection | Falco |
| Continuous workload scanning | Trivy Operator |
| Security and availability monitoring | Prometheus |
| Security visualization | Grafana |
| Security reporting | Jenkins |

---

## Supporting Platform

The following technologies support application delivery and deployment. They are not presented as security scanners by themselves.

| Function | Technology |
|---|---|
| Application framework | Spring Boot |
| Build and dependency management | Maven |
| Source control | Git and GitHub |
| Pipeline orchestration | Jenkins |
| Containerization | Docker |
| Container registry | Docker Hub |
| Container orchestration | Kubernetes |
| Local Kubernetes cluster | Minikube |
| Database | MySQL |

---

## Repository Structure

```text
timesheet-project/
├── ci/
│   ├── devsecops_report.py
│   └── runtime_checks.py
├── docs/
├── kubernetes/
│   ├── app/
│   └── network-policies/
├── monitoring/
├── pipeline/
│   └── Jenkinsfile
├── reports/
├── screenshots/
├── security/
│   ├── gauntlt/
│   ├── kyverno/
│   └── vault/
├── src/
├── Dockerfile
├── docker-compose.yml
├── pom.xml
└── README.md
```

---



Application database credentials are retrieved from Vault at runtime through a dedicated Kubernetes service account and a least-privilege Vault policy.
