---
name: container-registries
description: Manage container registries including ECR, ACR, GCR, and Docker Hub. 
category: Security & Systems
source: antigravity
tags: [ai, agent, workflow, template, image, security, vulnerability, docker, aws, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/container-registries
---


# Container Registries

Store, manage, and distribute container images across cloud and self-hosted registries.

## When to Use This Skill

Use this skill when:
- Pushing and pulling container images
- Configuring registry authentication
- Setting up image retention policies
- Managing private container registries
- Implementing image scanning and security

## Prerequisites

Confirm account/region/repository and image digest before pushing, publishing, granting cross-account access or enabling deletion policies. Preview cleanup candidates and preserve deployment/rollback digests. ACR retention and geo-replication require a supported SKU (the Standard setup above does not enable every later feature). Google cleanup policy files require the current CLI schema; validate the illustrative object before use. The Harbor archive/flags and Docker Content Trust are historical examples, not universal current signing instructions. TLS alone does not authorize registry clients: configure authentication/access controls before network exposure, and do not run both same-name registry examples simultaneously.

- Docker or Podman installed
- Cloud CLI tools (AWS CLI, az, gcloud) for respective registries
- Appropriate IAM permissions

## Docker Hub

### Authentication

```bash
# Login
docker login

# Login with token
echo "$DOCKER_TOKEN" | docker login -u username --password-stdin
```

### Push/Pull Images

```bash
# Tag image
docker tag myapp:latest username/myapp:latest

# Push
docker push username/myapp:latest

# Pull
docker pull username/myapp:latest
```

### Automated Builds

Configure in Docker Hub UI:
1. Connect GitHub/Bitbucket repository
2. Set build rules (branch → tag mapping)
3. Configure build context and Dockerfile path

## Amazon ECR

### Setup

```bash
# Create repository
aws ecr create-repository \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256

# Get registry URI
REGISTRY=$(aws ecr describe-repositories \
  --repository-names myapp \
  --query 'repositories[0].repositoryUri' \
  --output text | cut -d'/' -f1)
```

### Authentication

```bash
# Login (Docker)
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin $REGISTRY

# Login with credential helper
# Add to ~/.docker/config.json:
{
  "credHelpers": {
    "123456789.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"
  }
}
```

### Push/Pull

```bash
# Tag and push
docker tag myapp:latest $REGISTRY/myapp:latest
docker push $REGISTRY/myapp:latest

# Pull
docker pull $REGISTRY/myapp:latest
```

### Lifecycle Policy

```bash
# Create lifecycle policy
aws ecr put-lifecycle-policy \
  --repository-name myapp \
  --lifecycle-policy-text '{
    "rules": [
      {
        "rulePriority": 1,
        "description": "Keep last 10 images",
        "selection": {
          "tagStatus": "any",
          "countType": "imageCountMoreThan",
          "countNumber": 10
        },
        "action": {
          "type": "expire"
        }
      }
    ]
  }'
```

### Repository Policy

```bash
# Allow cross-account access
aws ecr set-repository-policy \
  --repository-name myapp \
  --policy-text '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "CrossAccountPull",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::OTHER_ACCOUNT:root"
        },
        "Action": [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
      }
    ]
  }'
```

## Azure Container Registry (ACR)

### Setup

```bash
# Create registry
az acr create \
  --resource-group mygroup \
  --name myregistry \
  --sku Standard \
  --admin-enabled false

# Get login server
az acr show --name myregistry --query loginServer -o tsv
```

### Authentication

```bash
# Login with Azure CLI
az acr login --name myregistry

# Login with service principal
printf '%s' "$SP_PASSWORD" | docker login myregistry.azurecr.io \
  -u "$SP_APP_ID" --password-stdin

# Get access token
az acr login --name myregistry --expose-token
```

### Push/Pull

```bash
# Tag and push
docker tag myapp:latest myregistry.azurecr.io/myapp:latest
docker push myregistry.azurecr.io/myapp:latest

# ACR Build (build in cloud)
az acr build \
  --registry myregistry \
  --image myapp:latest \
  --file Dockerfile .
```

### Retention Policy

```bash
# Enable retention policy
az acr config retention update \
  --registry myregistry \
  --status enabled \
  --days 30 \
  --type UntaggedManifests
```

### Geo-Replication

```bash
# Enable replication
az acr replication create \
  --registry myregistry \
  --location westeurope

# List replications
az acr replication list --registry myregistry
```

## Google Container Registry (GCR) / Artifact Registry

### Setup (Artifact Registry)

```bash
# Create repository
gcloud artifacts repositories create myrepo \
  --repository-format=docker \
  --location=us-central1 \
  --description="Docker repository"
```

### Au
