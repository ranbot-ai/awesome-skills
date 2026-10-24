---
name: devops-pipeline-builder
description: Design and implement CI/CD pipelines, Docker configurations, deployment strategies, and infrastructure automation with production-ready patterns. 
category: Document Processing
source: antigravity
tags: [node, api, claude, ai, automation, workflow, template, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/devops-pipeline-builder
---

## When to Use
- Use when this upstream workflow matches the user's stated goal.
- Use when the task requires the procedures documented in this skill.

# DevOps Pipeline Builder

Act as a DevOps engineer; do not claim personal deployment experience. You design for reliability, speed, and security — in that order.

## Decision Framework

Before writing any pipeline/config, establish:

1. **Project type**: Web app, API, library, microservice, monolith?
2. **Language/stack**: What build tools? What test framework?
3. **Deployment target**: Docker, K8s, VM, serverless, static?
4. **Environment strategy**: dev → staging → production?
5. **Compliance needs**: SOC2? HIPAA? Any audit requirements?
6. **Team size**: 1 person vs 50 devs changes the complexity budget

## Pipeline Patterns

Pin actions and base images to reviewed immutable versions for the target runner. Examples are templates, not evidence of current versions or deployment success. Restrict write permissions to trusted push events; protected environment approval and concurrency must match the project.

### GitHub Actions — Standard Web App

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'npm'
      - run: npm ci
      - run: npm test
      - run: npm run lint
      # Security audit
      - run: npm audit --audit-level=high
      
  build-and-push:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  deploy:
    needs: build-and-push
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: |
          # Add deployment commands here
          echo "Deployment placeholder: no deployment has occurred"
```

### Docker — Multi-stage Production Build

```dockerfile
# Stage 1: Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# Stage 2: Production
FROM node:22-alpine AS runner
WORKDIR /app
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 appuser

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
# Prune development dependencies in a reviewed production dependency stage.
COPY --from=builder /app/package.json ./

USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "dist/server.js"]
```

## Deployment Strategy Decision Tree

```
Is zero-downtime required?
├── Yes
│   ├── Have load balancer/ingress?
│   │   ├── Yes → Blue/Green or Rolling Update
│   │   └── No → Provision verified routing/health checks before promising zero downtime
│   └── Database migrations?
│       ├── Yes → Backward-compatible migrations first
│       └── No → Simple rolling update
└── No
    ├── Is it a dev/staging env?
    │   └── Yes → Direct push, recreate containers
    └── No → Why not? Add zero-downtime.
```

## Common Anti-Patterns to Avoid

| Anti-Pattern | Why It's Bad | Fix |
|---|---|---|
| `latest` tag in production | Non-reproducible, untraceable | Use SHA or semver tags |
| Build secrets in Dockerfile | Visible in image layers | BuildKit secret/SSH mounts; never secret ARG/ENV |
| No health checks | Orchestration can't detect failures | Add HEALTHCHECK |
| Running as root | Security risk | Create non-root user |
| Giant Docker images | Slow pulls, attack surface | Multi-stage builds, alpine |
| No `.dockerignore` | Slow builds, leaked secrets | Create comprehensive `.dockerignore` |
| Hardcoded env vars | Inflexible, unsecretive | Runtime env injection |
| No pipeline caching | Slow CI, wasted compute | Cache layers and dependencies |

## Infrastructure Checklist

For any production deployment, verify:

- [ ] Separate liveness from readiness; avoid restarting healthy processes merely because a dependency is down
- [ ] Graceful shutdown (SIGTERM handling)
- [ ] Structured logging (JSON, correlation IDs)
- [ ] Secrets management with least privilege, encryption and rotation; never commit plaintext Secrets manifests
- [ ] Resource limits set (CPU/memory requests and limits)
- [ ] Monito
