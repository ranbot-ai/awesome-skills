---
name: aws-cloudtrail
description: Configure AWS CloudTrail for audit logging. Set up organization trails and event analysis. Use when auditing AWS activity. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, llm, template, design, security, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-cloudtrail
---


# AWS CloudTrail

Audit AWS account activity with CloudTrail for compliance, security investigation, and operational troubleshooting.

## When to Use

- Enabling organization-wide audit logging across all AWS accounts
- Investigating security incidents or unauthorized API activity
- Meeting compliance requirements for SOC 2, HIPAA, PCI DSS, or FedRAMP
- Setting up automated alerting on sensitive AWS API calls
- Querying historical AWS activity for forensic analysis

## Prerequisites and Change Scope

Verify the AWS identity, partition, region and organization management/delegated-administrator permissions before mutation. All names, account IDs and ARNs below are synthetic placeholders; choose a globally unique owned bucket. Have a working KMS key policy permitting the selected CloudTrail trail and authorized readers, an existing CloudWatch log group and scoped role/trust policy before passing their ARNs. The snippets do not provision those dependencies. Review paid data-event/Lake/Athena scope and retention costs first. Export existing policies/selectors/lifecycle settings and merge intended changes; put-* operations can replace existing configuration. Never apply expiration to audit evidence under a legal hold.

## Create an Organization Trail

```bash
# Create the S3 bucket for log storage
aws s3api create-bucket \
  --bucket org-cloudtrail-audit-logs \
  --region us-east-1
# Apply bucket policy allowing CloudTrail to write
aws s3api put-bucket-policy \
  --bucket org-cloudtrail-audit-logs \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AWSCloudTrailAclCheck",
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:GetBucketAcl",
        "Resource": "arn:aws:s3:::org-cloudtrail-audit-logs",
        "Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit-trail"}}
      },
      {
        "Sid": "AWSCloudTrailWrite",
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": ["arn:aws:s3:::org-cloudtrail-audit-logs/AWSLogs/123456789012/*", "arn:aws:s3:::org-cloudtrail-audit-logs/AWSLogs/o-exampleorgid/*"],
        "Condition": {
          "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit-trail"}
        }
      }
    ]
  }'
# Block public access on the audit bucket
aws s3api put-public-access-block \
  --bucket org-cloudtrail-audit-logs \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# Enable version history (not WORM/tamper prevention)
aws s3api put-bucket-versioning \
  --bucket org-cloudtrail-audit-logs \
  --versioning-configuration Status=Enabled
# Enable server-side encryption
aws s3api put-bucket-encryption \
  --bucket org-cloudtrail-audit-logs \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "alias/cloudtrail-key"}}]
  }'
# Set lifecycle policy for log retention
aws s3api put-bucket-lifecycle-configuration \
  --bucket org-cloudtrail-audit-logs \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "TransitionToGlacier",
        "Status": "Enabled",
        "Filter": {"Prefix": "AWSLogs/"},
        "Transitions": [
          {"Days": 90, "StorageClass": "GLACIER"}
        ]
      },
      {
        "ID": "ExpireOldLogs",
        "Status": "Enabled",
        "Filter": {"Prefix": "AWSLogs/"},
        "Expiration": {"Days": 2555}
      }
    ]
  }'
# Create the organization trail
aws cloudtrail create-trail \
  --name org-audit-trail \
  --s3-bucket-name org-cloudtrail-audit-logs \
  --is-organization-trail \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:alias/cloudtrail-key \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail:* \
  --cloud-watch-logs-role-arn arn:aws:iam::123456789012:role/CloudTrail-CWLogs-Role
# Start logging
aws cloudtrail start-logging --name org-audit-trail
```

The organization prefix must use the real organization ID and the trail ARN must use the management account ID. Log-file validation detects changes; it does not prevent deletion. Versioning alone is not immutable retention. Validate Object Lock/legal-hold design separately where required.

## Event Selectors for Management and Data Events

```bash
# Configure advanced event selectors for granular control
aws cloudtrail put-event-selectors \
  --trail-name org-audit-trail \
  --advanced-event-selectors '[
    {
      "Name": "AllManagementEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]}
      ]
    },
    {
      "Name": "S3DataEventsForSensitiveBuckets",
    
