---
name: aws-secrets-manager
description: Store and rotate secrets in AWS Secrets Manager. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, workflow, template, image, security, aws, gcp]
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
- IAM policy limited to needed Secrets Manager actions and exact secret ARNs, plus required KMS permissions
- For rotation: Lambda execution role and VPC access to target services
- Python 3.9+ with `boto3` for SDK examples

## Secret Creation and Management

Create the referenced files privately (mode0600) using a secret-input/editor workflow, keep them out of Git and logs, and remove them according to the local secret-handling policy after use. Never put secret values directly into shell history or process arguments. `get-secret-value` prints plaintext: use only when explicitly needed in a private terminal; prefer consuming values inside the application. Confirm account/region/exact ARN before writes, rotation or scheduled deletion. Updating SecretString alone does not change the actual database password; use tested rotation for credentials.

```bash
# Create a secret with JSON structure
aws secretsmanager create-secret \
  --name myapp/production/database \
  --description "Production database credentials" \
  --secret-string file://database-secret.json \
  --tags '[{"Key":"Environment","Value":"production"},{"Key":"Team","Value":"platform"}]'
# Create a secret with KMS encryption (custom key)
aws secretsmanager create-secret \
  --name myapp/production/api-key \
  --description "Third-party API key" \
  --secret-string file://api-key.txt \
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
  --secret-string file://database-secret-updated.json
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
  --rotation-rules '{"ScheduleExpression":"rate(30 days)"}'
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
from psycopg2 import sql
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
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError("Rotation token must carry AWSPENDING")
    if step == "create
