---
name: gcp-audit-logs
description: Configure GCP Cloud Audit Logs for compliance. Set up log routing and BigQuery analysis. Use when auditing GCP activity. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, template, security, gcp, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-audit-logs
---


# GCP Audit Logs

Audit GCP activity with Cloud Audit Logs for compliance, security investigation, and operational monitoring.

## Audit Log Types

```yaml
log_types:
  admin_activity:
    description: API calls that modify resource configuration or metadata
    enabled: Always (cannot be disabled)
    retention: 400 days (default)
    cost: No charge
    examples:
      - Creating or deleting VM instances
      - Changing IAM policies
      - Modifying firewall rules

  data_access:
    description: API calls that read resource configuration, metadata, or user data
    enabled: Must be explicitly enabled (except BigQuery)
    retention: 30 days (default)
    cost: Can be significant at high volume
    subtypes:
      ADMIN_READ: Read resource configuration/metadata
      DATA_READ: Read user-provided data
      DATA_WRITE: Write user-provided data

  system_event:
    description: Actions performed by GCP systems on behalf of resources
    enabled: Always (cannot be disabled)
    retention: 400 days (default)
    cost: No charge
    examples:
      - Live migration of VM instances
      - Automatic scaling events

  policy_denied:
    description: Actions denied by VPC Service Controls or organization policies
    enabled: Always (cannot be disabled)
    retention: 400 days (default)
    cost: No charge
```

## Enable Data Access Logs for an Organization

```bash
# Get current org IAM policy
gcloud organizations get-iam-policy ORG_ID --format=json > org-policy.json

# Add audit config to org-policy.json:
# {
#   "auditConfigs": [
#     {
#       "service": "allServices",
#       "auditLogConfigs": [
#         {"logType": "ADMIN_READ"},
#         {"logType": "DATA_READ"},
#         {"logType": "DATA_WRITE"}
#       ]
#     }
#   ],
#   ...existing bindings...
# }

# Apply the updated policy
gcloud organizations set-iam-policy ORG_ID org-policy.json

# Enable data access logs for specific services at project level
gcloud projects get-iam-policy PROJECT_ID --format=json > project-policy.json

# Example: enable only for Cloud Storage and BigQuery
# {
#   "auditConfigs": [
#     {
#       "service": "storage.googleapis.com",
#       "auditLogConfigs": [
#         {"logType": "DATA_READ"},
#         {"logType": "DATA_WRITE"}
#       ]
#     },
#     {
#       "service": "bigquery.googleapis.com",
#       "auditLogConfigs": [
#         {"logType": "DATA_READ"},
#         {"logType": "DATA_WRITE"}
#       ]
#     }
#   ]
# }

gcloud projects set-iam-policy PROJECT_ID project-policy.json
```

## Configure Log Sinks for Export

```bash
# Create BigQuery dataset for audit log export
bq mk --dataset \
  --description "Audit log export" \
  --default_table_expiration 0 \
  --location US \
  PROJECT_ID:audit_logs

# Create organization-level log sink to BigQuery
gcloud logging sinks create org-audit-bigquery \
  bigquery.googleapis.com/projects/PROJECT_ID/datasets/audit_logs \
  --organization=ORG_ID \
  --include-children \
  --log-filter='logName:"cloudaudit.googleapis.com"'

# Get the sink writer identity and grant BigQuery access
SINK_SA=$(gcloud logging sinks describe org-audit-bigquery \
  --organization=ORG_ID --format='value(writerIdentity)')

bq add-iam-policy-binding \
  --member="$SINK_SA" \
  --role="roles/bigquery.dataEditor" \
  PROJECT_ID:audit_logs

# Create Cloud Storage sink for long-term archive
gsutil mb -l US -b on gs://org-audit-logs-archive
gsutil retention set 7y gs://org-audit-logs-archive

gcloud logging sinks create org-audit-storage \
  storage.googleapis.com/org-audit-logs-archive \
  --organization=ORG_ID \
  --include-children \
  --log-filter='logName:"cloudaudit.googleapis.com"'

STORAGE_SA=$(gcloud logging sinks describe org-audit-storage \
  --organization=ORG_ID --format='value(writerIdentity)')

gsutil iam ch "$STORAGE_SA:objectCreator" gs://org-audit-logs-archive

# Create Pub/Sub sink for real-time streaming to SIEM
gcloud pubsub topics create audit-log-stream

gcloud logging sinks create org-audit-pubsub \
  pubsub.googleapis.com/projects/PROJECT_ID/topics/audit-log-stream \
  --organization=ORG_ID \
  --include-children \
  --log-filter='logName:"cloudaudit.googleapis.com" AND (protoPayload.methodName:"delete" OR protoPayload.methodName:"setIamPolicy" OR severity>=WARNING)'

PUBSUB_SA=$(gcloud logging sinks describe org-audit-pubsub \
  --organization=ORG_ID --format='value(writerIdentity)')

gcloud pubsub topics add-iam-policy-binding audit-log-stream \
  --member="$PUBSUB_SA" \
  --role="roles/pubsub.publisher"
```

## Logging Queries (Cloud Logging Explorer)

```bash
# View admin activity logs for the last 24 hours
gcloud logging read 'logName:"cloudaudit.googleapis.com/activity"
  AND timestamp>="2024-01-01T00:00:00Z"' \
  --project=PROJECT_ID \
  --format=json \
  --limit=100

# Find IAM policy changes
gcloud logging read 'logName:"cloudaudit.googleapis.com/activity"
  AND protoPayload.methodName="SetIamPolicy"' \
  --project=PROJECT_ID \
  --freshness=7d

# Find resource d
