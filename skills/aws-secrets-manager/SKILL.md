---
name: aws-secrets-manager
description: Store and rotate secrets in AWS Secrets Manager. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, template, image, security, aws, gcp, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-secrets-manager
---


# AWS Secrets Manager

Securely store, manage, and rotate secrets in AWS.

## When to Use This Skill

Use this skill when:
- Storing database credentials, API keys, or tokens in AWS
- Implementing automatic credential rotation for RDS or other services
- Replacing hardcoded secrets in application code or config files
- Integrating secrets into ECS, EKS, or Lambda workloads
- Meeting compliance requirements for secret management and rotation

## Prerequisites

- AWS account with appropriate IAM permissions
- AWS CLI v2 installed and configured
- IAM policy allowing `secretsmanager:*` actions (or scoped permissions)
- For rotation: Lambda execution role and VPC access to target services
- Python 3.9+ with `boto3` for SDK examples

## Secret Creation and Management

```bash
# Create a secret with JSON structure
aws secretsmanager create-secret \
  --name myapp/production/database \
  --description "Production database credentials" \
  --secret-string '{"username":"dbadmin","password":"S3cur3P@ssw0rd!","engine":"postgres","host":"db.internal.example.com","port":5432,"dbname":"myapp"}' \
  --tags '[{"Key":"Environment","Value":"production"},{"Key":"Team","Value":"platform"}]'

# Create a secret with KMS encryption (custom key)
aws secretsmanager create-secret \
  --name myapp/production/api-key \
  --description "Third-party API key" \
  --secret-string "ak_live_xxxxxxxxxxxx" \
  --kms-key-id alias/secrets-key

# Create a binary secret (certificates, keys)
aws secretsmanager create-secret \
  --name myapp/production/tls-cert \
  --secret-binary fileb://server.pfx

# Get secret value
aws secretsmanager get-secret-value \
  --secret-id myapp/production/database \
  --query 'SecretString' --output text | jq .

# Get a specific version
aws secretsmanager get-secret-value \
  --secret-id myapp/production/database \
  --version-stage AWSPREVIOUS

# Update secret value
aws secretsmanager put-secret-value \
  --secret-id myapp/production/database \
  --secret-string '{"username":"dbadmin","password":"N3wS3cur3P@ss!","engine":"postgres","host":"db.internal.example.com","port":5432,"dbname":"myapp"}'

# List all secrets
aws secretsmanager list-secrets \
  --filters Key=name,Values=myapp/production

# Delete secret (with recovery window)
aws secretsmanager delete-secret \
  --secret-id myapp/production/old-key \
  --recovery-window-in-days 7

# Restore a deleted secret
aws secretsmanager restore-secret \
  --secret-id myapp/production/old-key

# Tag a secret
aws secretsmanager tag-resource \
  --secret-id myapp/production/database \
  --tags '[{"Key":"RotationEnabled","Value":"true"}]'
```

## Automatic Rotation

### Enable Rotation

```bash
# Enable rotation with an existing Lambda function
aws secretsmanager rotate-secret \
  --secret-id myapp/production/database \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRDSPostgreSQLRotation \
  --rotation-rules '{"AutomaticallyAfterDays":30,"ScheduleExpression":"rate(30 days)"}'

# Trigger immediate rotation
aws secretsmanager rotate-secret \
  --secret-id myapp/production/database

# Check rotation status
aws secretsmanager describe-secret \
  --secret-id myapp/production/database \
  --query '{RotationEnabled:RotationEnabled,RotationLambdaARN:RotationLambdaARN,RotationRules:RotationRules,LastRotatedDate:LastRotatedDate}'
```

### Lambda Rotation Function

```python
"""rotation_function.py - Custom rotation Lambda for database credentials."""

import boto3
import json
import logging
import psycopg2

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Secrets Manager rotation handler.

    The rotation process has four steps:
    1. createSecret - Generate new secret value
    2. setSecret - Apply the new secret to the target service
    3. testSecret - Verify the new secret works
    4. finishSecret - Mark rotation complete
    """
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    client = boto3.client('secretsmanager')

    metadata = client.describe_secret(SecretId=secret_arn)
    if not metadata.get('RotationEnabled'):
        raise ValueError(f"Secret {secret_arn} does not have rotation enabled")

    versions = metadata.get('VersionIdsToStages', {})
    if token not in versions:
        raise ValueError(f"Secret version {token} has no stage for rotation")

    if step == "createSecret":
        create_secret(client, secret_arn, token)
    elif step == "setSecret":
        set_secret(client, secret_arn, token)
    elif step == "testSecret":
        test_secret(client, secret_arn, token)
    elif step == "finishSecret":
        finish_secret(client, secret_arn, token)
    else:
        raise ValueError(f"Invalid step: {step}")


def create_secret(client, secret_arn, token):
    """Generate a new secret value."""
    current = client.get_secret_value(
        SecretId=secret_arn, VersionStage="AWSCURRENT"
    )
    current_dict = jso
