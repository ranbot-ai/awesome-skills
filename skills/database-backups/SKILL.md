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

DB_NAME="mydb"
DB_USER="backup_user"
DB_PASS="${MYSQL_BACKUP_PASSWORD}"
BACKUP_DIR="/backups/mysql"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="${BACKUP_DIR}/${DB_NAME}_${DATE}.sql.gz"

mkdir -p "$BACKUP_DIR"

mysqldump -u "$DB_USER" -p"$DB_PASS" \
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

BACKUP_DIR="/backups/mysql/full_$(date +%Y%m%d)"

xtrabackup --backup \
  --user=backup_user \
  --password "$MYSQL_BACKUP_PASSWORD" # from your vault; never hardcode \
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
sudo find /var/lib/mysql -mindepth 1 -delete  # empty the data dir; snapshots must exist (see Limitations)
xtrabackup --move-back --target-dir=/backups/mysql/full_20250115
sudo chown -R mysql:mysql /var/lib/mysql
sudo systemctl start mysql
```

## MongoDB Backups

### Logical Backup with mongodump

```bash
#!/bin/bash
# mongo_backup.sh — MongoDB backup
set -euo pipefail

MONGO_URI="mongodb://backup_user:${MONGO_BACKUP_PASSWORD}@localhost:27017"
BACKUP_DIR="/backups/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
TARGET="${BACKUP_DIR}/${DATE}"

mkdir -p "$BACKUP_DIR"

# Full backup with compression
mongodump --uri="$MONGO_URI" --gzip --out="$TARGET"

echo "[$(date)] MongoDB backup complete: $TARGET"
```

### MongoDB Restore

```bash
# Restore all databases
mongorestore --uri="mongodb://admin:secret@localhost:27017" \
  --gzip --drop /backups/mongodb/20250115_020000/

# Restore a single database
mongorestore --uri="mongodb://admin:secret@localhost:27017" \
  --gzip --drop --db mydb /backups/mongodb/20250115_020000/mydb/

# Restore a single collection
mongorestore --uri="mongodb://admin:secret@localhost:27017" \
  --gzip --drop --db mydb --collection users \
  /backups/mongodb/20250115_020000/mydb/users.bson.gz
```

## Upload to S3

```bash
#!/bin/bash
# s3_upload.sh — Upload backups to S3
set -euo pi
