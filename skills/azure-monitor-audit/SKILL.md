---
name: azure-monitor-audit
description: Configure Azure Monitor and Activity Log for auditing. Set up diagnostic settings and log analytics. Use when auditing Azure activity. 
category: Document Processing
source: antigravity
tags: [react, markdown, api, ai, agent, llm, template, document, security, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-monitor-audit
---


# Azure Monitor Audit

Audit Azure activity with Monitor, Activity Logs, and Log Analytics for compliance, security, and operational visibility.

## When to Use

- Enabling centralized audit logging across Azure subscriptions
- Meeting compliance requirements for SOC 2, HIPAA, PCI DSS, or ISO 27001
- Investigating security incidents or unauthorized activity in Azure
- Setting up alerting on administrative and security events
- Building compliance dashboards and automated evidence collection

These are paid provisioning/configuration examples requiring authorized Azure access, not privilege-free checks. Confirm tenant/subscription, data residency, cost/retention and alert recipients before writes. Inspect supported categories for each resource and verify actual ingestion after setup; Entra SigninLogs/AuditLogs require their own connector/licensing, and SQL diagnostics do not enable SQL auditing by themselves. Never place real PagerDuty integration keys in committed command URLs.

## Create Log Analytics Workspace

```bash
# Create resource group for audit resources
az group create \
  --name rg-audit \
  --location eastus

# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group rg-audit \
  --workspace-name audit-workspace \
  --location eastus \
  --retention-time 365 \
  --sku PerGB2018

# Get workspace ID for later use
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group rg-audit \
  --workspace-name audit-workspace \
  --query id -o tsv)

# Verify required data connectors separately; workspace creation does not ingest logs.
```

Diagnostic-setting retentionPolicy no longer enforces storage retention (retired September30,2025); use reviewed Azure Storage lifecycle policies and separately configure Log Analytics table/workspace retention. Retention is not immutability and diagnostic settings do not establish regulatory compliance.

## Configure Diagnostic Settings for Subscription Activity Log

```bash
# Export subscription activity log to Log Analytics
az monitor diagnostic-settings subscription create \
  --name activity-log-to-workspace \
  --location global \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "ServiceHealth", "enabled": true},
    {"category": "Alert", "enabled": true},
    {"category": "Recommendation", "enabled": true},
    {"category": "Policy", "enabled": true},
    {"category": "Autoscale", "enabled": true},
    {"category": "ResourceHealth", "enabled": true}
  ]'

# Also archive to storage account for long-term retention
az storage account create \
  --name auditlogsarchive \
  --resource-group rg-audit \
  --location eastus \
  --sku Standard_GRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

az monitor diagnostic-settings subscription create \
  --name activity-log-to-storage \
  --location global \
  --storage-account /subscriptions/{sub}/resourceGroups/rg-audit/providers/Microsoft.Storage/storageAccounts/auditlogsarchive \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true}
  ]'
```

## Resource-Level Diagnostic Settings

```bash
# Enable diagnostics for Azure Key Vault
az monitor diagnostic-settings create \
  --name keyvault-audit \
  --resource /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault} \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "AuditEvent", "enabled": true},
    {"category": "AzurePolicyEvaluationDetails", "enabled": true}
  ]' \
  --metrics '[
    {"category": "AllMetrics", "enabled": true}
  ]'

# Enable diagnostics for Azure SQL Database
az monitor diagnostic-settings create \
  --name sql-audit \
  --resource /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{server}/databases/{db} \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "SQLSecurityAuditEvents", "enabled": true},
    {"category": "SQLInsights", "enabled": true},
    {"category": "AutomaticTuning", "enabled": true}
  ]'

# Enable diagnostics for Azure App Service
az monitor diagnostic-settings create \
  --name appservice-audit \
  --resource /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app} \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "AppServiceHTTPLogs", "enabled": true},
    {"category": "AppServiceAuditLogs", "enabled": true},
    {"category": "AppServiceIPSecAuditLogs", "enabled": true},
    {"category": "AppServicePlatformLogs", "enabled": true}
  ]'

# NSG diagnostic events below are not flow logs. New deployments should use
# Network Watcher VNet flow logs; new NSG flow logs cannot be created.
# Inspect supported diagnostic categories before enabling these event categories.
az monitor diagnostic-settings create \
  --name nsg-diagnostic-events \
  --resource /subscriptions/{sub}/resourceGr
