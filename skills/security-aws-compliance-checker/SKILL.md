---
name: aws-compliance-checker
description: Automated compliance checking against CIS, PCI-DSS, HIPAA, and SOC 2 benchmarks 
category: Security & Systems
source: antigravity
tags: [python, api, ai, document, security, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/security/aws-compliance-checker
---


# AWS Compliance Checker

Automated compliance validation against industry standards including CIS AWS Foundations, PCI-DSS, HIPAA, and SOC 2.

## When to Use

Use this skill when you need to validate AWS compliance against industry standards, prepare for audits, or maintain continuous compliance monitoring.

## Supported Frameworks

**CIS AWS Foundations Benchmark**
- Identity and Access Management
- Logging and Monitoring
- Networking
- Data Protection

**PCI-DSS (Payment Card Industry)**
- Network security
- Access controls
- Encryption
- Monitoring and logging

**HIPAA (Healthcare)**
- Access controls
- Audit controls
- Data encryption
- Transmission security

**SOC 2**
- Security
- Availability
- Confidentiality
- Privacy

## CIS AWS Foundations Checks

### Identity & Access Management (1.x)

```bash
#!/bin/bash
# cis-iam-checks.sh

echo "=== CIS IAM Compliance Checks ==="

# 1.1: Root account usage
echo "1.1: Checking root account usage..."
root_usage=$(aws iam get-credential-report --output text | \
  awk -F, 'NR==2 {print $5,$11}')
echo "  Root password last used: $root_usage"

# 1.2: MFA on root account
echo "1.2: Checking root MFA..."
root_mfa=$(aws iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled' --output text)
echo "  Root MFA enabled: $root_mfa"

# 1.3: Unused credentials
echo "1.3: Checking for unused credentials (>90 days)..."
aws iam get-credential-report --output text | \
  awk -F, 'NR>1 {
    if ($5 != "N/A" && $5 != "no_information") {
      cmd = "date -d \"" $5 "\" +%s"
      cmd | getline last_used
      close(cmd)
      now = systime()
      days = (now - last_used) / 86400
      if (days > 90) print "  ⚠️  " $1 ": " int(days) " days inactive"
    }
  }'

# 1.4: Access keys rotated
echo "1.4: Checking access key age..."
aws iam list-users --query 'Users[*].UserName' --output text | \
while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate]' \
    --output text | \
  while read key_id create_date; do
    age_days=$(( ($(date +%s) - $(date -d "$create_date" +%s)) / 86400 ))
    if [ $age_days -gt 90 ]; then
      echo "  ⚠️  $user: Key $key_id is $age_days days old"
    fi
  done
done

# 1.5-1.11: Password policy
echo "1.5-1.11: Checking password policy..."
policy=$(aws iam get-account-password-policy 2>&1)
if echo "$policy" | grep -q "NoSuchEntity"; then
  echo "  ❌ No password policy configured"
else
  echo "  ✓ Password policy exists"
  echo "$policy" | jq '.PasswordPolicy | {
    MinimumPasswordLength,
    RequireSymbols,
    RequireNumbers,
    RequireUppercaseCharacters,
    RequireLowercaseCharacters,
    MaxPasswordAge,
    PasswordReusePrevention
  }'
fi

# 1.12-1.14: MFA for IAM users
echo "1.12-1.14: Checking IAM user MFA..."
aws iam get-credential-report --output text | \
  awk -F, 'NR>1 && $4=="false" {print "  ⚠️  " $1 ": No MFA"}'
```

### Logging (2.x)

```bash
#!/bin/bash
# cis-logging-checks.sh

echo "=== CIS Logging Compliance Checks ==="

# 2.1: CloudTrail enabled
echo "2.1: Checking CloudTrail..."
trails=$(aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' \
  --output text)

if [ -z "$trails" ]; then
  echo "  ❌ No CloudTrail configured"
else
  echo "$trails" | while read name multi_region validation; do
    echo "  Trail: $name"
    echo "    Multi-region: $multi_region"
    echo "    Log validation: $validation"
    
    # Check if logging
    status=$(aws cloudtrail get-trail-status --name "$name" \
      --query 'IsLogging' --output text)
    echo "    Is logging: $status"
  done
fi

# 2.2: CloudTrail log file validation
echo "2.2: Checking log file validation..."
aws cloudtrail describe-trails \
  --query 'trailList[?LogFileValidationEnabled==`false`].Name' \
  --output text | \
while read trail; do
  echo "  ⚠️  $trail: Log validation disabled"
done

# 2.3: S3 bucket for CloudTrail
echo "2.3: Checking CloudTrail S3 bucket access..."
aws cloudtrail describe-trails \
  --query 'trailList[*].S3BucketName' --output text | \
while read bucket; do
  public=$(aws s3api get-bucket-acl --bucket "$bucket" 2>&1 | \
    grep -c "AllUsers")
  if [ "$public" -gt 0 ]; then
    echo "  ❌ $bucket: Publicly accessible"
  else
    echo "  ✓ $bucket: Not public"
  fi
done

# 2.4: CloudTrail integrated with CloudWatch Logs
echo "2.4: Checking CloudWatch Logs integration..."
aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,CloudWatchLogsLogGroupArn]' \
  --output text | \
while read name log_group; do
  if [ "$log_group" = "None" ]; then
    echo "  ⚠️  $name: Not integrated with CloudWatch Logs"
  else
    echo "  ✓ $name: Integrated with CloudWatch"
  fi
done

# 2.5: AWS Config enabled
echo "2.5: Checking AWS Config..."
recorders=$(aws configservice describe-configuration-recorders \
  --query 'ConfigurationRecorders[*].name' --output text)

if [ -z "$recorders" ]; then
  echo "  ❌ AWS Config not enabled"
else
  echo " 
