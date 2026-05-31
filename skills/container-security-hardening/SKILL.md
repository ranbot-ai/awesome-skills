---
name: container-security-hardening
description: Harden Docker/container images and runtime deployments with secure base images, non-root users, CVE scanning, SBOM/signing, seccomp/AppArmor, and Kubernetes pod security controls. Use for Dockerfile s
category: Security & Systems
source: antigravity
tags: [python, react, node, api, ai, workflow, template, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/container-security-hardening
---


# Container Security Hardening Skill

A production-focused guide for building, scanning, and running containers securely — from Dockerfile authoring through runtime enforcement and supply chain integrity.

---

## When to Use This Skill

- User mentions Docker security, container hardening, or Dockerfile security review
- User asks about distroless images, non-root containers, or read-only filesystems
- User wants to scan images for CVEs with Trivy, Grype, or Snyk
- User mentions seccomp, AppArmor, Linux capabilities, or runtime security
- User asks "is my Dockerfile secure?" or "how do I reduce my image attack surface?"
- User wants to sign/verify images with Cosign or generate SBOMs
- User asks about Kubernetes pod security, NetworkPolicy, or RBAC hardening
- User says "fix container CVEs" or "harden my container for production"

## When NOT to Use This Skill

- The user is primarily asking about GitHub Actions CI/CD → recommend `github-actions-advanced`
- The user needs general Docker usage help (not security) → recommend `docker-expert`
- The user is working with Kubernetes orchestration beyond security → recommend `kubernetes-architect`
- The user needs application-level security (SQL injection, XSS) → recommend `api-security-best-practices`

---

## Step 1: Understand Context Before Responding

When invoked, first detect the current state:

```bash
# Find Dockerfiles in the project
find . -name "Dockerfile*" -not -path "*/node_modules/*" | head -10

# Check for existing security tooling
ls .trivyignore .hadolint.yaml .snyk docker-compose*.yml 2>/dev/null

# Inspect base images currently in use
grep -r "^FROM" $(find . -name "Dockerfile*") 2>/dev/null

# Check if Kubernetes manifests exist
find . -name "*.yaml" -path "*/k8s/*" -o -name "*.yaml" -path "*/manifests/*" | head -10
```

Then adapt recommendations to:
- The tech stack (Node, Python, Go, Java — affects base image choice)
- Whether this is Docker-only or Kubernetes-deployed
- The CI platform in use (for scanner integration)
- The existing base images and how far they are from best practice

---

## The Five Layers of Container Security

```
1. Image Build        → Minimal base, no secrets, non-root, read-only FS
2. Image Scanning     → CVE scanning, SBOM, secret detection, Dockerfile lint
3. Runtime Security   → Capabilities, seccomp, AppArmor, resource limits
4. Supply Chain       → Signed images, pinned digests, trusted registries
5. Kubernetes Layer   → Pod Security Admission, NetworkPolicy, RBAC, Kyverno
```

> Work through layers in order — hardening the image first gives the most leverage.
> See `references/base-image-comparison.md` for a full size/CVE trade-off table.

---

## Layer 1: Dockerfile Hardening

### 1.1 Use a Minimal Base Image

```dockerfile
# ❌ AVOID — massive attack surface (~100–200 CVEs typical)
FROM ubuntu:latest
FROM node:20

# ✅ BETTER — slim variants (glibc, smaller apt footprint)
FROM node:20-slim
FROM python:3.12-slim

# ✅ BEST — distroless (no shell, no package manager, built-in nonroot user)
FROM gcr.io/distroless/nodejs20-debian12
FROM gcr.io/distroless/python3-debian12
FROM gcr.io/distroless/static-debian12   # Go/Rust fully-static binaries

# ✅ ALSO GREAT — Alpine (musl libc; verify app compatibility first)
FROM alpine:3.20

# ✅ ZERO ATTACK SURFACE — for fully static binaries only
FROM scratch
```

See `references/base-image-comparison.md` for the full trade-off matrix.

### 1.2 Multi-Stage Build — Separate Build from Runtime

Never ship build tools, compilers, or dev dependencies in a production image.

```dockerfile
# syntax=docker/dockerfile:1

# ── Stage 1: Install & Build ──────────────────────────────
FROM node:20-slim AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci                          # Install all deps (including devDeps)
COPY . .
RUN npm run build && npm prune --production

# ── Stage 2: Runtime — minimal, no build tools ────────────
FROM gcr.io/distroless/nodejs20-debian12@sha256:<digest>
LABEL org.opencontainers.image.source="https://github.com/org/repo"
LABEL org.opencontainers.image.revision="${BUILD_SHA}"
LABEL org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /build/dist        ./dist
COPY --from=builder --chown=nonroot:nonroot /build/node_modules ./node_modules
USER nonroot:nonroot                # UID 65532 — built into distroless
EXPOSE 3000
CMD ["dist/server.js"]
```

**Go / Rust static binary pattern:**
```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app .

FROM scratch                        # Zero attack surface
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

### 1.3 Run as Non-Root User

```dockerfile
# For debian/ubuntu-based images — create dedicated user
RUN groupadd -r appgroup --gid 10001 && \
    useradd 
