---
name: aws-secrets-rotation
description: Automate AWS secrets rotation for RDS, API keys, and credentials 
category: Security & Systems
source: antigravity
tags: [python, javascript, node, api, ai, automation, template, document, security, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/security/aws-secrets-rotation
---


# AWS Secrets Rotation

Automate rotation of secrets, credentials, and API keys using AWS Secrets Manager and Lambda.

## When to Use

Use this skill when you need to implement automated secrets rotation, manage credentials securely, or comply with security policies requiring regular key rotation.

## Supported Secret Types

**AWS Services**
- RDS database credentials
- DocumentDB credentials
- Redshift credentials
- ElastiCache credentials

**Third-Party Services**
- API keys
- OAuth tokens
- SSH keys
- Custom credentials

## Secrets Manager Setup

### Create a Secret

```bash
# Create RDS secret
aws secretsmanager create-secret \
  --name prod/db/mysql \
  --description "Production MySQL credentials" \
  --secret-string '{
    "username": "admin",
    "password": "CHANGE_ME",
    "engine": "mysql",
    "host": "mydb.cluster-abc.us-east-1.rds.amazonaws.com",
    "port": 3306,
    "dbname": "myapp"
  }'

# Create API key secret
aws secretsmanager create-secret \
  --name prod/api/stripe \
  --secret-string '{
    "api_key": "sk_live_xxxxx",
    "webhook_secret": "whsec_xxxxx"
  }'

# Create secret from file
aws secretsmanager create-secret \
  --name prod/ssh/private-key \
  --secret-binary fileb://~/.ssh/id_rsa
```

### Retrieve Secrets

```bash
# Get secret value
aws secretsmanager get-secret-value \
  --secret-id prod/db/mysql \
  --query 'SecretString' --output text

# Get specific field
aws secretsmanager get-secret-value \
  --secret-id prod/db/mysql \
  --query 'SecretString' --output text | \
  jq -r '.password'

# Get binary secret
aws secretsmanager get-secret-value \
  --secret-id prod/ssh/private-key \
  --query 'SecretBinary' --output text | \
  base64 -d > private-key.pem
```

## Automatic Rotation Setup

### Enable RDS Rotation

```bash
# Enable automatic rotation (30 days)
aws secretsmanager rotate-secret \
  --secret-id prod/db/mysql \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRDSMySQLRotation \
  --rotation-rules AutomaticallyAfterDays=30

# Rotate immediately
aws secretsmanager rotate-secret \
  --secret-id prod/db/mysql

# Check rotation status
aws secretsmanager describe-secret \
  --secret-id prod/db/mysql \
  --query 'RotationEnabled'
```

### Lambda Rotation Function

```python
# lambda_rotation.py
import boto3
import json
import os

secrets_client = boto3.client('secretsmanager')
rds_client = boto3.client('rds')

def lambda_handler(event, context):
    """Rotate RDS MySQL password"""
    
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    # Get current secret
    current = secrets_client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(current['SecretString'])
    
    if step == "createSecret":
        # Generate new password
        new_password = generate_password()
        secret['password'] = new_password
        
        # Store as pending
        secrets_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret),
            VersionStages=['AWSPENDING']
        )
    
    elif step == "setSecret":
        # Update RDS password
        rds_client.modify_db_instance(
            DBInstanceIdentifier=secret['dbInstanceIdentifier'],
            MasterUserPassword=secret['password'],
            ApplyImmediately=True
        )
    
    elif step == "testSecret":
        # Test new credentials
        import pymysql
        conn = pymysql.connect(
            host=secret['host'],
            user=secret['username'],
            password=secret['password'],
            database=secret['dbname']
        )
        conn.close()
    
    elif step == "finishSecret":
        # Mark as current
        secrets_client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage='AWSCURRENT',
            MoveToVersionId=token,
            RemoveFromVersionId=current['VersionId']
        )
    
    return {'statusCode': 200}

def generate_password(length=32):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for _ in range(length))
```

### Custom Rotation for API Keys

```python
# api_key_rotation.py
import boto3
import requests
import json

secrets_client = boto3.client('secretsmanager')

def rotate_stripe_key(secret_arn, token, step):
    """Rotate Stripe API key"""
    
    current = secrets_client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(current['SecretString'])
    
    if step == "createSecret":
        # Create new Stripe key via API
        response = requests.post(
            'https://api.stripe.com/v1/api_keys',
            auth=(secret['api_key'], ''),
            data={'name': f'rotated-{token[:8]}'}
        )
        new_key = response.json()['secret']
        
        secret['api_key'] = new_key
        secrets_client.put_secret_value(
      
