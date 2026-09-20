---
name: gcp-cloud-sql
description: Provision Cloud SQL and Spanner databases. Configure high availability, backups, and security. Use when deploying managed databases on GCP. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, template, security, kubernetes, gcp, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-cloud-sql
---


# GCP Cloud SQL

Deploy and manage fully managed relational databases (PostgreSQL, MySQL, SQL Server) on Google Cloud.

## When to Use

- Running production relational databases without managing replication, patching, or backups
- Migrating on-premises PostgreSQL or MySQL workloads to a managed service
- Applications requiring ACID transactions, relational schemas, and SQL query support
- Workloads that need automated high availability with regional failover

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and authenticated
- Cloud SQL Admin API and Service Networking API enabled
- IAM role `roles/cloudsql.admin` for full management

```bash
gcloud services enable sqladmin.googleapis.com servicenetworking.googleapis.com
```

## Instance Tiers Reference

| Tier | vCPUs | Memory | Use Case |
|------|-------|--------|----------|
| db-f1-micro | Shared | 0.6 GB | Dev/test only |
| db-g1-small | Shared | 1.7 GB | Low-traffic staging |
| db-custom-2-8192 | 2 | 8 GB | Small production |
| db-custom-4-16384 | 4 | 16 GB | Medium production |
| db-custom-8-32768 | 8 | 32 GB | High-traffic production |

## Create a PostgreSQL Instance

```bash
gcloud sql instances create prod-db \
  --database-version=POSTGRES_16 \
  --tier=db-custom-4-16384 \
  --region=us-central1 \
  --availability-type=REGIONAL \
  --storage-type=SSD --storage-size=100GB --storage-auto-increase \
  --backup-start-time=02:00 --enable-point-in-time-recovery \
  --retained-backups-count=14 \
  --maintenance-window-day=SUN --maintenance-window-hour=4 \
  --database-flags=max_connections=200,log_min_duration_statement=1000 \
  --root-password=$(openssl rand -base64 24) \
  --labels=env=production,team=backend

gcloud sql databases create myapp --instance=prod-db --charset=UTF8
gcloud sql users create appuser --instance=prod-db \
  --password=$(openssl rand -base64 24)
```

## Create a MySQL Instance

```bash
gcloud sql instances create mysql-prod \
  --database-version=MYSQL_8_0 \
  --tier=db-custom-4-16384 --region=us-central1 \
  --availability-type=REGIONAL \
  --storage-type=SSD --storage-size=100GB --storage-auto-increase \
  --backup-start-time=02:00 --enable-bin-log --retained-backups-count=14 \
  --database-flags=slow_query_log=on,long_query_time=2,max_connections=500 \
  --root-password=$(openssl rand -base64 24)
```

## Private IP Configuration

```bash
# Allocate IP range and create private connection
gcloud compute addresses create google-managed-services \
  --global --purpose=VPC_PEERING --prefix-length=16 --network=my-vpc

gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services --network=my-vpc

# Create instance with private IP only
gcloud sql instances create private-db \
  --database-version=POSTGRES_16 --tier=db-custom-2-8192 \
  --region=us-central1 \
  --network=projects/${PROJECT_ID}/global/networks/my-vpc \
  --no-assign-ip --availability-type=REGIONAL \
  --storage-type=SSD --storage-size=50GB --storage-auto-increase
```

## Read Replicas

```bash
# Same-region replica
gcloud sql instances create prod-db-replica-1 \
  --master-instance-name=prod-db --tier=db-custom-4-16384 \
  --region=us-central1 --availability-type=ZONAL

# Cross-region replica for DR
gcloud sql instances create prod-db-replica-eu \
  --master-instance-name=prod-db --tier=db-custom-4-16384 \
  --region=europe-west1 --availability-type=ZONAL

# Promote a replica to standalone (disaster recovery)
gcloud sql instances promote-replica prod-db-replica-eu
```

## Backups and Restore

```bash
gcloud sql backups create --instance=prod-db --description="pre-migration"
gcloud sql backups list --instance=prod-db

# Point-in-time recovery
gcloud sql instances clone prod-db prod-db-pitr \
  --point-in-time="2026-03-23T10:00:00Z"

# Export / import
gcloud sql export sql prod-db gs://my-bucket/export.sql.gz --database=myapp
gcloud sql import sql prod-db gs://my-bucket/export.sql.gz --database=myapp
```

## Cloud SQL Auth Proxy

```bash
curl -o cloud-sql-proxy \
  https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.11.0/cloud-sql-proxy.linux.amd64
chmod +x cloud-sql-proxy

./cloud-sql-proxy ${PROJECT_ID}:us-central1:prod-db --port=5432 --auto-iam-authn

# Unix socket (for Kubernetes sidecar pattern)
./cloud-sql-proxy ${PROJECT_ID}:us-central1:prod-db --unix-socket=/tmp/cloudsql
psql "host=/tmp/cloudsql/${PROJECT_ID}:us-central1:prod-db user=appuser dbname=myapp"
```

## Connection Methods Summary

| Method | Use Case | Requirement |
|--------|----------|-------------|
| Public IP + SSL | Dev/test access | Authorized networks configured |
| Cloud SQL Auth Proxy | Production on GCE/GKE | SA with `roles/cloudsql.client` |
| Private IP | VPC-native apps | VPC peering configured |
| Cloud SQL Connector lib | App-level integration | SA credentials |

## Terraform Configuration

```hcl
resource "google_sql_database_instance" "main" {
  name             = "prod-db"
  database_version = "POS
