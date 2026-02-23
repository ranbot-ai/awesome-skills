---
name: aws-iam-best-practices
description: IAM policy review, hardening, and least privilege implementation 
category: Security & Systems
source: antigravity
tags: [python, ai, workflow, template, document, security, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/security/aws-iam-best-practices
---


# AWS IAM Best Practices

Review and harden IAM policies following AWS security best practices and least privilege principles.

## When to Use

Use this skill when you need to review IAM policies, implement least privilege access, or harden IAM security.

## Core Principles

**Least Privilege**
- Grant minimum permissions needed
- Use managed policies when possible
- Avoid wildcard (*) permissions
- Regular access reviews

**Defense in Depth**
- Enable MFA for all users
- Use IAM roles instead of access keys
- Implement service control policies (SCPs)
- Enable CloudTrail for audit

**Separation of Duties**
- Separate admin and user roles
- Use different roles for different environments
- Implement approval workflows
- Regular permission audits

## IAM Security Checks

### Find Overly Permissive Policies

```bash
# List policies with full admin access
aws iam list-policies --scope Local \
  --query 'Policies[*].[PolicyName,Arn]' --output table | \
  grep -i admin

# Find policies with wildcard actions
aws iam list-policies --scope Local --query 'Policies[*].Arn' --output text | \
while read arn; do
  version=$(aws iam get-policy --policy-arn "$arn" \
    --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" \
    --version-id "$version" --query 'PolicyVersion.Document')
  if echo "$doc" | grep -q '"Action": "\*"'; then
    echo "Wildcard action in: $arn"
  fi
done

# Find inline policies (should use managed policies)
aws iam list-users --query 'Users[*].UserName' --output text | \
while read user; do
  policies=$(aws iam list-user-policies --user-name "$user" \
    --query 'PolicyNames' --output text)
  if [ -n "$policies" ]; then
    echo "Inline policies on user $user: $policies"
  fi
done
```

### MFA Enforcement

```bash
# List users without MFA
aws iam get-credential-report --output text | \
  awk -F, 'NR>1 && $4=="false" {print $1}'

# Check if MFA is required in policies
aws iam list-policies --scope Local --query 'Policies[*].Arn' --output text | \
while read arn; do
  version=$(aws iam get-policy --policy-arn "$arn" \
    --query 'Policy.DefaultVersionId' --output text)
  doc=$(aws iam get-policy-version --policy-arn "$arn" \
    --version-id "$version" --query 'PolicyVersion.Document')
  if echo "$doc" | grep -q "aws:MultiFactorAuthPresent"; then
    echo "MFA enforced in: $arn"
  fi
done

# Enable MFA for a user (returns QR code)
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name user-mfa \
  --outfile /tmp/qr.png \
  --bootstrap-method QRCodePNG
```

### Access Key Management

```bash
# Find old access keys (>90 days)
aws iam list-users --query 'Users[*].UserName' --output text | \
while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate,Status]' \
    --output text | \
  while read key_id create_date status; do
    age_days=$(( ($(date +%s) - $(date -d "$create_date" +%s)) / 86400 ))
    if [ $age_days -gt 90 ]; then
      echo "$user: Key $key_id is $age_days days old"
    fi
  done
done

# Rotate access key
OLD_KEY="AKIAIOSFODNN7EXAMPLE"
USER="myuser"

# Create new key
NEW_KEY=$(aws iam create-access-key --user-name "$USER")
echo "New key created. Update applications, then run:"
echo "aws iam delete-access-key --user-name $USER --access-key-id $OLD_KEY"

# Deactivate old key (test first)
aws iam update-access-key \
  --user-name "$USER" \
  --access-key-id "$OLD_KEY" \
  --status Inactive
```

### Role and Policy Analysis

```bash
# List unused roles (no activity in 90 days)
aws iam list-roles --query 'Roles[*].[RoleName,RoleLastUsed.LastUsedDate]' \
  --output text | \
while read role last_used; do
  if [ "$last_used" = "None" ]; then
    echo "Never used: $role"
  fi
done

# Find roles with trust relationships to external accounts
aws iam list-roles --query 'Roles[*].RoleName' --output text | \
while read role; do
  trust=$(aws iam get-role --role-name "$role" \
    --query 'Role.AssumeRolePolicyDocument')
  if echo "$trust" | grep -q '"AWS":'; then
    echo "External trust: $role"
  fi
done

# Analyze policy permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/myuser \
  --action-names s3:GetObject s3:PutObject \
  --resource-arns arn:aws:s3:::mybucket/*
```

## IAM Policy Templates

### Least Privilege S3 Access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/user-data/${aws:username}/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-bucket",
      "Condition": {
        "StringLike": {
          "s3:prefix": "user-data/${aws:username}/*"
        }
      }
    }
  ]
}
```

### MFA-Required Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
 
