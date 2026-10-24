---
name: database-backups
description: Implement database backup strategies. Configure automated backups, retention, and recovery testing. Use when designing backup and recovery procedures. 
category: Document Processing
source: antigravity
tags: [api, ai, agent, template, design, document, security, docker, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/database-backups
---


# Database Backups

Implement comprehensive, automated database backup strategies with tested recovery procedures.

## When to Use

- You are deploying a new database and need a backup plan from day one.
- You need to automate nightly or hourly backups for PostgreSQL, MySQL, or MongoDB.
- You want to ship backups to S3-compatible object storage with retention policies.
- You are building or verifying disaster recovery runbooks.

Confirm source/restore targets, RPO/RTO, retention and rollback. These scripts are partial: write dumps to private temporary files and promote only after successful exit and integrity checks; upload only completed manifests, not every old/partial file recursively. Verify remote checksums and a restore before deleting local copies. Lifecycle replacement affects the whole configured bucket and must preserve other policies/noncurrent versions. Restore-test row counts are application-specific smoke checks, not full recovery proof. Use protected client configuration/secret mechanisms rather than passwords in process arguments; Mongo URI credentials need proper encoding.

## Prerequisites

- Database client tools installed (`pg_dump`, `mysqldump`, `mongodump`).
- AWS CLI or `restic` for remote storage.
- `cron` or systemd timers for scheduling.
- An S3 bucket (or S3-compatible endpoint) for offsite backups.

## Backup Types

| Type | Description | Frequency | Use Case |
|---|---|---|---|
| Full | Complete database copy | Weekly | Baseline for restores |
| Incremental | Changes since last backup | Daily | Reduce storage and time |
| Transaction log / WAL | Continuous log shipping | Continuous | Point-in-time recovery (PITR) |
| Snapshot | Storage-level snapshot (EBS, ZFS) | Daily | Fast full restores |

## PostgreSQL Backups

### Logical Backup with pg_dump

```bash
#!/bin/bash
# pg_backup.sh — PostgreSQL logical backup
set -euo pipefail
umask 077

DB_NAME="mydb"
DB_USER="backup_user"
DB_HOST="localhost"
BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="${BACKUP_DIR}/${DB_NAME}_${DATE}.dump"

mkdir -p "$BACKUP_DIR"

# Custom compressed format (recommended for selective restore)
pg_dump -h "$DB_HOST" -U "$DB_USER" -Fc -Z6 "$DB_NAME" > "$FILENAME"

echo "[$(date)] PostgreSQL backup complete: $FILENAME ($(du -h "$FILENAME" | cut -f1))"
```

### Physical Backup with pg_basebackup

```bash
#!/bin/bash
# pg_basebackup.sh — PostgreSQL physical backup for PITR
set -euo pipefail
umask 077

BACKUP_DIR="/backups/postgres/base_$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

pg_basebackup \
  -h localhost \
  -U replicator \
  -D "$BACKUP_DIR" \
  --wal-method=stream \
  --checkpoint=fast \
  --progress \
  --verbose

echo "[$(date)] Base backup complete: $BACKUP_DIR"
```

### PostgreSQL Restore

```bash
# Restore from custom-format dump
pg_restore -h localhost -U myapp -d mydb --clean --if-exists /backups/postgres/mydb_20250115_020000.dump

# Restore a single table
pg_restore -h localhost -U myapp -d mydb -t orders /backups/postgres/mydb_20250115_020000.dump

# Restore from plain SQL
psql -h localhost -U myapp -d mydb < /backups/postgres/mydb_20250115.sql
```

## MySQL Backups

### Logical Backup with mysqldump

```bash
#!/bin/bash
# mysql_backup.sh — MySQL logical backup
set -euo pipefail
umask 077

DB_NAME="mydb"
DB_USER="backup_user"
MYSQL_CNF="/etc/backup/mysql.cnf" # root/backup-owned mode 0600, credentials from approved secret storage
BACKUP_DIR="/backups/mysql"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="${BACKUP_DIR}/${DB_NAME}_${DATE}.sql.gz"

mkdir -p "$BACKUP_DIR"

mysqldump --defaults-extra-file="$MYSQL_CNF" -u "$DB_USER" \
  --single-transaction \
  --routines \
  --triggers \
  --events \
  "$DB_NAME" | gzip > "$FILENAME"

echo "[$(date)] MySQL backup complete: $FILENAME ($(du -h "$FILENAME" | cut -f1))"
```

### Physical Backup with Percona XtraBackup

```bash
#!/bin/bash
# xtrabackup.sh — MySQL physical backup
set -euo pipefail
umask 077

BACKUP_DIR="/backups/mysql/full_$(date +%Y%m%d)"

xtrabackup --backup \
  --defaults-extra-file=/etc/backup/mysql.cnf \
  --user=backup_user \
  --target-dir="$BACKUP_DIR"

xtrabackup --prepare --target-dir="$BACKUP_DIR"

echo "[$(date)] XtraBackup complete: $BACKUP_DIR"
```

### MySQL Restore

```bash
# Restore from compressed mysqldump
gunzip < /backups/mysql/mydb_20250115_020000.sql.gz | mysql -u root -p mydb

# Restore from XtraBackup
sudo systemctl stop mysql
ls /var/lib/mysql/*  # verify this is the correct data dir first
# Preserve/rename the old data directory under an approved recovery runbook;
# do not recursively delete it to make a restore fit.
xtrabackup --copy-back --target-dir=/backups/mysql/full_20250115
sudo chown -R mysql:mysql /var/lib/mysql
sudo systemctl start mysql
```

## MongoDB Backups

### Logical Backup with mongodump

```bash
#!/bin/bash
# mongo_backup.sh — MongoDB backup
set -euo pipefail
umask 077

MONGO_URI="mongodb://backup_user:${MONGO_BACKUP_PASSWORD}@localhost:27017"
BACKUP_DIR="/backups/mongodb"
DATE=$(date +
