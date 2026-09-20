---
name: azure-sql
description: Provision Azure SQL Database and Cosmos DB. Configure security, backups, and replication. Use when deploying managed databases on Azure. 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, template, security, vulnerability, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-sql
---


# Azure SQL

Deploy and manage Azure SQL Database, Elastic Pools, and Cosmos DB. Covers server provisioning, firewall rules, geo-replication, backup strategies, performance tuning, security hardening, and Terraform configurations.

## Prerequisites

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login and set subscription
az login
az account set --subscription "my-subscription-id"

# Create resource group
az group create --name database-rg --location eastus
```

## SQL Server and Database Creation

### Create SQL Server

```bash
# Create logical SQL server
az sql server create \
  --resource-group database-rg \
  --name myapp-sqlserver \
  --location eastus \
  --admin-user sqladmin \
  --admin-password 'S3cur3P@ssw0rd!' \
  --enable-public-network false \
  --minimal-tls-version 1.2

# Enable Azure AD authentication
az sql server ad-admin create \
  --resource-group database-rg \
  --server-name myapp-sqlserver \
  --display-name "SQL Admins" \
  --object-id "{aad-group-object-id}"

# Enable Azure AD only authentication (disable SQL auth)
az sql server ad-only-auth enable \
  --resource-group database-rg \
  --name myapp-sqlserver
```

### Create Databases

```bash
# Create General Purpose database
az sql db create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-db \
  --edition GeneralPurpose \
  --compute-model Serverless \
  --auto-pause-delay 60 \
  --min-capacity 0.5 \
  --max-size 32GB \
  --backup-storage-redundancy Geo \
  --zone-redundant false

# Create Business Critical database for production
az sql db create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-prod-db \
  --edition BusinessCritical \
  --service-objective BC_Gen5_4 \
  --max-size 256GB \
  --backup-storage-redundancy Geo \
  --zone-redundant true \
  --read-scale Enabled

# Create Hyperscale database for large workloads
az sql db create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-analytics-db \
  --edition Hyperscale \
  --service-objective HS_Gen5_4 \
  --ha-replicas 2

# List databases on server
az sql db list \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --output table
```

### Elastic Pools

```bash
# Create elastic pool
az sql elastic-pool create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-pool \
  --edition GeneralPurpose \
  --capacity 4 \
  --db-max-capacity 2 \
  --db-min-capacity 0.25 \
  --max-size 256GB \
  --zone-redundant false

# Move database into elastic pool
az sql db update \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-db \
  --elastic-pool myapp-pool

# Monitor elastic pool usage
az sql elastic-pool list-dbs \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-pool \
  --output table
```

## Firewall Rules and Network Security

```bash
# Allow Azure services
az sql server firewall-rule create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

# Allow specific IP range (office network)
az sql server firewall-rule create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name AllowOffice \
  --start-ip-address 203.0.113.0 \
  --end-ip-address 203.0.113.255

# Allow your current client IP
az sql server firewall-rule create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name AllowMyIP \
  --start-ip-address "$(curl -s ifconfig.me)" \
  --end-ip-address "$(curl -s ifconfig.me)"

# Create VNet rule for subnet access
az sql server vnet-rule create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name AllowAppSubnet \
  --vnet-name spoke-prod-vnet \
  --subnet app-subnet

# List firewall rules
az sql server firewall-rule list \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --output table

# Remove a firewall rule
az sql server firewall-rule delete \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name AllowMyIP
```

## Geo-Replication and Failover

```bash
# Create failover group with secondary server
az sql server create \
  --resource-group database-rg \
  --name myapp-sqlserver-secondary \
  --location westus \
  --admin-user sqladmin \
  --admin-password 'S3cur3P@ssw0rd!'

az sql failover-group create \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-failover-group \
  --partner-server myapp-sqlserver-secondary \
  --partner-resource-group database-rg \
  --failover-policy Automatic \
  --grace-period 1 \
  --add-db myapp-prod-db

# Check failover group status
az sql failover-group show \
  --resource-group database-rg \
  --server myapp-sqlserver \
  --name myapp-failover-group \
  --output table

# Manual failover (for testing or planned maintenance)
az sql failover-group set-primary \
  --resource-group database-rg \
  --server myapp-sqlserver-sec
