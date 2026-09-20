---
name: aws-cloudtrail
description: Configure AWS CloudTrail for audit logging. Set up organization trails and event analysis. Use when auditing AWS activity. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, llm, template, security, aws, rag, cro]
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
        "Resource": "arn:aws:s3:::org-cloudtrail-audit-logs"
      },
      {
        "Sid": "AWSCloudTrailWrite",
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::org-cloudtrail-audit-logs/AWSLogs/*",
        "Condition": {
          "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
        }
      }
    ]
  }'

# Block public access on the audit bucket
aws s3api put-public-access-block \
  --bucket org-cloudtrail-audit-logs \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable versioning for tamper protection
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
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
        {"Field": "resources.ARN", "StartsWith": [
          "arn:aws:s3:::sensitive-data-bucket/",
          "arn:aws:s3:::pii-bucket/",
          "arn:aws:s3:::financial-data/"
        ]}
      ]
    },
    {
      "Name": "LambdaInvocations",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
      ]
    },
    {
      "Name": "DynamoDBDataEvents",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::DynamoDB::Table"]}
      ]
    }
  ]'
```

## CloudWatch Alerts for Sensitive Activity

```bash
# Create metric filter for unauthorized API calls
aws logs put-metric-filter \
  --log-group-name CloudTrail \
  --filter-name UnauthorizedAPICalls \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICalls,metricNamespace=CloudTrailMetrics,metricValue=1

# Create alarm for unauthorized calls
aws cloudwatch put-metric-alarm \
  --alarm-name UnauthorizedAPICallsAlarm \
  --metric-name UnauthorizedAPICall
