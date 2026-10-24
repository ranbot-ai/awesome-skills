---
name: aws-ecs-fargate
description: Deploy containers on ECS and Fargate. Configure task definitions, services, and load balancing. Use when running containerized workloads on AWS. 
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, template, image, security, docker, kubernetes, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-ecs-fargate
---


# AWS ECS & Fargate

Run containerized applications on Amazon ECS with Fargate serverless compute or EC2 launch type.

## When to Use This Skill

- Deploying Docker containers to AWS without managing servers (Fargate)
- Running microservices with service discovery and load balancing
- Setting up blue/green or rolling deployments for containerized apps
- Configuring auto-scaling for container workloads
- Migrating from docker-compose or Kubernetes to ECS
- Troubleshooting task failures, health check issues, or networking problems

## Prerequisites

- AWS CLI v2 installed and configured
- Docker installed for building and pushing images
- Least-privilege IAM permissions for the selected ECS/ECR/ELB/log operations and `iam:PassRole` restricted to the exact task roles
- An ECR repository for storing container images
- A VPC with subnets and an ALB (see aws-vpc (`aws-vpc`))

Confirm account, region, budget, cluster/service ownership, deployment window and rollback before changes. Use immutable image digests or versioned tags for reproducible deployments. Private tasks need verified NAT or VPC endpoint access for ECR, logs, secrets and SSM as used. Fargate ALB target groups must use target type `ip`. Execution roles fetch image/log/secret dependencies; task roles grant application and optional ECS Exec permissions. ECS Exec also requires a supported task platform, SSM channels and authorized audited access; enabling a flag is insufficient. The examples reference roles, networking, discovery and ALB resources that are not defined here.

## Cluster Setup

```bash
# Create an ECS cluster with Container Insights enabled
aws ecs create-cluster \
  --cluster-name production \
  --capacity-providers FARGATE FARGATE_SPOT \
  --default-capacity-provider-strategy '[
    {"capacityProvider": "FARGATE", "weight": 1, "base": 2},
    {"capacityProvider": "FARGATE_SPOT", "weight": 3}
  ]' \
  --settings '[{"name": "containerInsights", "value": "enabled"}]'

# List clusters
aws ecs list-clusters

# Describe cluster details
aws ecs describe-clusters --clusters production --include STATISTICS ATTACHMENTS
```

## Push Image to ECR

```bash
# Create ECR repository
aws ecr create-repository \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=KMS

# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build, tag, and push
docker build -t myapp:latest .
docker tag myapp:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

## Task Definition

```json
{
  "family": "myapp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::123456789012:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "myapp",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "PORT", "value": "8080"}
      ],
      "secrets": [
        {
          "name": "DB_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/db-password"
        },
        {
          "name": "API_KEY",
          "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/api-key"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/myapp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs",
          "awslogs-create-group": "true"
        }
      },
      "ulimits": [
        {"name": "nofile", "softLimit": 65536, "hardLimit": 65536}
      ]
    }
  ]
}
```

```bash
# Register the task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# List task definition revisions
aws ecs list-task-definitions --family-prefix myapp

# Deregister an old revision
aws ecs deregister-task-definition --task-definition myapp:1
```

## Create Service with ALB

```bash
# Create the CloudWatch log group first
aws logs create-log-group --log-group-name /ecs/myapp
aws logs put-retention-policy --log-group-name /ecs/myapp --retention-in-days 30

# Create ECS service with load balancer
aws ecs create-service \
  --cluster production \
  --service-name myapp \
  --task-definition myapp:2 \
  --desired-count 3 \
  --launch-ty
