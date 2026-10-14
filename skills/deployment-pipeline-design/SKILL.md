---
name: deployment-pipeline-design
description: Architecture patterns for multi-stage CI/CD pipelines with approval gates and deployment strategies. 
category: Document Processing
source: antigravity
tags: [python, api, ai, agent, automation, workflow, template, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/deployment-pipeline-design
---


# Deployment Pipeline Design

Architecture patterns for multi-stage CI/CD pipelines with approval gates and deployment strategies.

## Do not use this skill when

- The task is unrelated to deployment pipeline design
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

## Purpose

Design robust, secure deployment pipelines that balance speed with safety through proper stage organization and approval workflows.

## Use this skill when

- Design CI/CD architecture
- Implement deployment gates
- Configure multi-environment pipelines
- Establish deployment best practices
- Implement progressive delivery

## Pipeline Stages

### Standard Pipeline Flow

```
┌─────────┐   ┌──────┐   ┌─────────┐   ┌────────┐   ┌──────────┐
│  Build  │ → │ Test │ → │ Staging │ → │ Approve│ → │Production│
└─────────┘   └──────┘   └─────────┘   └────────┘   └──────────┘
```

### Detailed Stage Breakdown

1. **Source** - Code checkout
2. **Build** - Compile, package, containerize
3. **Test** - Unit, integration, security scans
4. **Staging Deploy** - Deploy to staging environment
5. **Integration Tests** - E2E, smoke tests
6. **Approval Gate** - Manual approval required
7. **Production Deploy** - Canary, blue-green, rolling
8. **Verification** - Health checks, monitoring
9. **Rollback** - Automated rollback on failure

## Approval Gate Patterns

### Pattern 1: Manual Approval

```yaml
# GitHub Actions
production-deploy:
  needs: staging-deploy
  environment:
    name: production
    url: https://app.example.com
  runs-on: ubuntu-latest
  steps:
    - name: Deploy to production
      run: |
        # Deployment commands
```

### Pattern 2: Delayed Deployment

```yaml
# GitLab CI
deploy:production:
  stage: deploy
  script:
    - deploy.sh production
  environment:
    name: production
  when: delayed
  start_in: 30 minutes
  only:
    - main
```

### Pattern 3: Multi-Approver

Configure the platform's actual protected-environment approval policy and verify who may approve or bypass it. For Azure, bind manual validation to the installed task version and its supported agentless job rather than placing it in an arbitrary deployment hook. Record required approvers and evidence; notifications alone are not approval.

## Deployment Strategies

### 1. Rolling Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 10
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 1
```

**Characteristics:**
- Gradual rollout
- Availability depends on readiness, capacity and compatible changes
- Easy rollback
- Best for most applications

### 2. Blue-Green Deployment

```yaml
# Blue (current)
kubectl apply -f blue-deployment.yaml
kubectl patch service my-app --type merge -p '{"spec":{"selector":{"app":"my-app","version":"blue"}}}'

# Green (new)
kubectl apply -f green-deployment.yaml
# Test green environment
kubectl patch service my-app --type merge -p '{"spec":{"selector":{"app":"my-app","version":"green"}}}'

# Rollback if needed
kubectl patch service my-app --type merge -p '{"spec":{"selector":{"app":"my-app","version":"blue"}}}'
```

**Characteristics:**
- Instant switchover
- Easy rollback
- Doubles infrastructure cost temporarily
- Good for high-risk deployments

### 3. Canary Deployment

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: my-app
spec:
  replicas: 10
  strategy:
    canary:
      steps:
      - setWeight: 10
      - pause: {duration: 5m}
      - setWeight: 25
      - pause: {duration: 5m}
      - setWeight: 50
      - pause: {duration: 5m}
      - setWeight: 100
```

**Characteristics:**
- Gradual traffic shift
- Risk mitigation
- Real user testing
- Requires service mesh or similar

### 4. Feature Flags

```python
from flagsmith import Flagsmith

flagsmith = Flagsmith(environment_key="API_KEY")

if flagsmith.has_feature("new_checkout_flow"):
    # New code path
    process_checkout_v2()
else:
    # Existing code path
    process_checkout_v1()
```

**Characteristics:**
- Deploy without releasing
- A/B testing
- Instant rollback
- Granular control

## Pipeline Orchestration

### Multi-stage implementation contract

Build once, record the commit and immutable artifact digest, run tests/security checks on that artifact, deploy to authorized staging, run integration checks, obtain configured production approval, then deploy that same digest with bounded progressive traffic. Each job must establish its own checkout, locked tools, scoped credentials and artifact transfer. Verify rollout and application metrics before promotion; do not immediately promote a canary and thereby skip its observation window. Notifications require an explicitly configured authorized recipient and destination.

## Pipeline Best Practices

1. **Fail fast** - Run quick tests first
2. **P
