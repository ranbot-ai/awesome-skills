---
name: container-scanning
description: Scan container images for vulnerabilities using Trivy, Grype, and cloud-native tools. 
category: Security & Systems
source: antigravity
tags: [python, react, api, ai, agent, template, document, image, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/container-scanning
---


# Container Scanning

Scan container images for vulnerabilities and security misconfigurations.

## When to Use This Skill

Use this skill when:
- Building container images
- Implementing container security gates
- Scanning registry images
- Meeting compliance requirements
- Hardening container deployments

## Prerequisites

- Container runtime (Docker, Podman)
- Container images to scan
- Scanning tool installation

## Tool Comparison

| Tool | License | Speed | Features |
|------|---------|-------|----------|
| Trivy | OSS | Fast | Comprehensive, IaC |
| Grype | OSS | Fast | Accurate, SBOM |
| Clair | OSS | Medium | Registry integration |
| Snyk Container | Commercial | Fast | Fix suggestions |
| Docker Scout | Commercial | Fast | GitHub integration |

## Trivy

### Installation

```bash
# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o /tmp/install-trivy.sh && sh /tmp/install-trivy.sh && rm /tmp/install-trivy.sh -s -- -b /usr/local/bin

# macOS
brew install trivy

# Docker
docker pull aquasec/trivy
```

### Image Scanning

```bash
# Scan local image
trivy image myapp:latest

# Scan remote image
trivy image nginx:1.25

# JSON output
trivy image --format json -o results.json myapp:latest

# Filter by severity
trivy image --severity HIGH,CRITICAL myapp:latest

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed myapp:latest

# Exit code on vulnerability
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

### Filesystem Scanning

```bash
# Scan project directory
trivy fs /path/to/project

# Scan Dockerfile
trivy config Dockerfile

# Scan Kubernetes manifests
trivy config k8s/
```

### Configuration

```yaml
# trivy.yaml
timeout: 10m
severity:
  - HIGH
  - CRITICAL
ignore-unfixed: true
exit-code: 1

vulnerability:
  type:
    - os
    - library

scan:
  file-patterns:
    - "Dockerfile"
    - "*.yaml"
```

### CI Integration

```yaml
# GitHub Actions
name: Container Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

## Grype

### Installation

```bash
# Linux/macOS
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh -o /tmp/install-grype.sh && sh /tmp/install-grype.sh && rm /tmp/install-grype.sh -s -- -b /usr/local/bin

# Homebrew
brew install grype
```

### Usage

```bash
# Scan image
grype myapp:latest

# Scan from SBOM
grype sbom:./sbom.json

# JSON output
grype myapp:latest -o json > results.json

# Filter severity
grype myapp:latest --fail-on high

# Scan directory
grype dir:/path/to/project
```

### Configuration

```yaml
# .grype.yaml
check-for-app-update: false
fail-on-severity: high
output: "json"
scope: "Squashed"

ignore:
  - vulnerability: CVE-2023-12345
    reason: "False positive"
    expires: "2024-12-31"
```

## Docker Scout

### Usage

```bash
# Enable Docker Scout
docker scout quickview myapp:latest

# Full CVE report
docker scout cves myapp:latest

# Compare images
docker scout compare myapp:v1 myapp:v2

# Recommendations
docker scout recommendations myapp:latest
```

### CI Integration

```yaml
- name: Docker Scout
  uses: docker/scout-action@v1
  with:
    command: cves
    image: ${{ env.IMAGE_NAME }}
    sarif-file: scout-results.sarif
    summary: true
```

## Registry Integration

### Amazon ECR

```bash
# Enable scan on push
aws ecr put-image-scanning-configuration \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true

# Get scan findings
aws ecr describe-image-scan-findings \
  --repository-name myapp \
  --image-id imageTag=latest

# Start manual scan
aws ecr start-image-scan \
  --repository-name myapp \
  --image-id imageTag=latest
```

### Azure ACR

```bash
# Enable Defender for Containers
az security pricing create \
  --name Containers \
  --tier Standard

# View scan results in Azure Portal or:
az acr repository show \
  --name myregistry \
  --image myapp:latest
```

### Google Artifact Registry

```bash
# Enable vulnerability scanning
gcloud artifacts repositories update myrepo \
  --location=us-central1 \
  --enable-vulnerability-scanning

# View vulnerabilities
gcloud artifacts docker images describe \
  us-central1-docker.pkg.dev/project/myrepo/myapp:latest \
  --show-package-vulnerability
```

## Admission Controllers

### OPA Gatekeeper

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
