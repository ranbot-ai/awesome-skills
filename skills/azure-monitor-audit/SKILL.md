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

# Enable audit solutions
az monitor log-analytics solution create \
  --resource-group rg-audit \
  --solution-type SecurityCenterFree \
  --workspace audit-workspace
```

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
    {"category": "Administrative", "enabled": true, "retentionPolicy": {"enabled": true, "days": 2555}},
    {"category": "Security", "enabled": true, "retentionPolicy": {"enabled": true, "days": 2555}}
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
    {"category": "AuditEvent", "enabled": true, "retentionPolicy": {"enabled": true, "days": 365}},
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

# Enable diagnostics for Network Security Groups
az monitor diagnostic-settings create \
  --name nsg-flow-logs \
  --resource /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{nsg} \
  --workspace "$WORKSPACE_ID" \
  --logs '[
    {"category": "NetworkSecurityGroupEvent", "enabled": true},
    {"category": "NetworkSecurityGroupRuleCounter", "enabled": true}
  ]'
```

## Azure Policy for Diagnostic Settings Enforcement

```bash
# Assign built-in policy to require diagnostic settings on Key Vaults
az policy assignment create \
  --name require-kv-diagnostics \
  --policy "951af2fa-529b-416e-ab6e-066fd85ac459" \
  --scope /subscriptions/{sub} \
  --params '{
    "logAnalytics": {"value": "'$WORKSPACE_ID'"},
    "effect": {"value": "DeployIfNotExists"}
  }'

# Assign policy to require diagnostic settings on SQL databases
az policy assignment create \
  --name requ
