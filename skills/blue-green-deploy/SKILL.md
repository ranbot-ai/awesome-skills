---
name: blue-green-deploy
description: Configure zero-downtime deployment strategies including blue-green, canary, and rolling deployments. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, template, image, security, kubernetes, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/blue-green-deploy
---


# Blue-Green & Deployment Strategies

Implement zero-downtime deployment patterns for production systems.

## Prerequisites

- Load balancer or ingress controller
- Container orchestration (K8s) or cloud platform
- CI/CD pipeline
- Health check endpoints

## Deployment Strategy Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT STRATEGIES                     │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  Blue-Green │   Canary    │   Rolling   │    Recreate      │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ Full env    │ Gradual %   │ Pod by pod  │ All at once      │
│ swap        │ rollout     │ replacement │                  │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ Instant     │ Slow, safe  │ Moderate    │ Fast, risky      │
│ rollback    │ rollback    │ rollback    │                  │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ 2x resources│ +10-25%     │ Same        │ Same             │
│ needed      │ resources   │ resources   │                  │
└─────────────┴─────────────┴─────────────┴──────────────────┘
```

## Blue-Green Deployment

### Concept

```
Before:
┌─────────┐     ┌───────────────┐
│  Users  │────▶│  Blue (v1)    │ ◀── Active
└─────────┘     └───────────────┘
                ┌───────────────┐
                │  Green (v2)   │ ◀── Staging
                └───────────────┘

After Switch:
┌─────────┐     ┌───────────────┐
│  Users  │     │  Blue (v1)    │ ◀── Standby
└─────────┘     └───────────────┘
      │         ┌───────────────┐
      └────────▶│  Green (v2)   │ ◀── Active
                └───────────────┘
```

### Kubernetes Implementation

```yaml
# blue-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-blue
  labels:
    app: myapp
    version: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
      version: blue
  template:
    metadata:
      labels:
        app: myapp
        version: blue
    spec:
      containers:
      - name: myapp
        image: myapp:v1.0.0
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
# green-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-green
  labels:
    app: myapp
    version: green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
      version: green
  template:
    metadata:
      labels:
        app: myapp
        version: green
    spec:
      containers:
      - name: myapp
        image: myapp:v2.0.0
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
# service.yaml - Switch by changing selector
apiVersion: v1
kind: Service
metadata:
  name: myapp
spec:
  selector:
    app: myapp
    version: blue  # Change to 'green' to switch
  ports:
  - port: 80
    targetPort: 8080
```

### Switch Script

```bash
#!/bin/bash
# blue-green-switch.sh

CURRENT=$(kubectl get svc myapp -o jsonpath='{.spec.selector.version}')
NEW_VERSION=$1

echo "Current version: $CURRENT"
echo "Switching to: $NEW_VERSION"

# Verify new deployment is ready
kubectl rollout status deployment/myapp-$NEW_VERSION

# Check health
HEALTH=$(kubectl exec -it deployment/myapp-$NEW_VERSION -- curl -s localhost:8080/health)
if [ "$HEALTH" != "ok" ]; then
  echo "Health check failed"
  exit 1
fi

# Switch traffic
kubectl patch svc myapp -p "{\"spec\":{\"selector\":{\"version\":\"$NEW_VERSION\"}}}"

echo "Switched to $NEW_VERSION"
```

### AWS ECS Blue-Green

```yaml
# AWS CodeDeploy appspec.yml
version: 0.0
Resources:
  - TargetService:
      Type: AWS::ECS::Service
      Properties:
        TaskDefinition: "arn:aws:ecs:region:account:task-definition/myapp:2"
        LoadBalancerInfo:
          ContainerName: "myapp"
          ContainerPort: 8080
Hooks:
  - BeforeInstall: "LambdaFunctionToValidateBeforeTrafficShift"
  - AfterInstall: "LambdaFunctionToValidateAfterTrafficShift"
  - AfterAllowTestTraffic: "LambdaFunctionToValidateTestTraffic"
  - BeforeAllowTraffic: "LambdaFunctionToValidateBeforeAllowTraffic"
  - AfterAllowTraffic: "LambdaFunctionToValidateAfterAllowTraffic"
```

## Canary Deployment

### Kubernetes with Istio

```yaml
# VirtualService for traffic splitting
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: myapp
spec:
  hosts:
  - myapp
  http:
  - match:
    - headers:
        x-canary:
          exact: "true"
    route:
    - destination:
        host: myapp
        subset: canary
  - route:
    - destination:
        host: myapp
        subset: stable
      weight: 90
    - destination:
        host: myapp
        subset: canary
      weight: 10
---
apiVersion: networking.istio.io/v1beta1
kind: Destination
