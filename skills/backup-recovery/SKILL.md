---
name: backup-recovery
description: Implement backup and recovery strategies. Configure rsync, Restic, and cloud backups. Use when designing data protection solutions. 
category: AI & Agents
source: antigravity
tags: [node, ai, agent, automation, workflow, template, design, security, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/backup-recovery
---


# Backup and Recovery

Implement comprehensive backup and recovery strategies using rsync, Restic, and cloud storage backends. Covers the 3-2-1 rule, automated scheduling, S3/B2 backends, encryption, restore procedures, and verification testing.

## When to Use

- Designing a backup strategy for servers, databases, or application data
- Setting up Restic for encrypted, deduplicated backups to local or cloud storage
- Automating backups with systemd timers or cron
- Restoring data after accidental deletion, corruption, or disaster
- Migrating data between environments using backup/restore workflows
- Verifying backup integrity and testing recovery procedures

## Prerequisites

- `rsync` installed (included in most Linux distributions)
- `restic` installed (v0.16+ recommended)
- Cloud CLI configured for the backend: AWS CLI for S3, `b2` CLI for Backblaze B2
- Sufficient storage at the backup destination (2-3x source size for retention)
- SSH access for remote rsync targets
- `systemd` or `cron` for scheduling

## The 3-2-1 Backup Rule

- **3** copies of your data (1 primary + 2 backups)
- **2** different storage media or types (e.g., local disk + cloud)
- **1** copy offsite (cloud storage, remote datacenter)

Confirm source/destination paths, retention ownership and recovery targets. A mirror with --delete propagates deletions and is not an independent historical backup; dry-run before destructive sync/prune. Never copy a running PostgreSQL data directory as a consistent backup: use pg_dump or a supported physical backup/snapshot protocol. Run pipelines in Bash with pipefail so failed dumps cannot become apparently successful empty snapshots. Restore to an isolated new database/path first; --clean deletes target objects. Keep repository credentials and recovery keys in a separate approved location; logs and backup data are sensitive.

## rsync Backups

### Basic Operations

```bash
# Sync a local directory to a backup location
rsync -avz --delete /data/ /backup/data/

# Flags explained:
# -a  archive mode (preserves permissions, ownership, timestamps, symlinks)
# -v  verbose output
# -z  compress data during transfer
# --delete  remove files at destination that no longer exist at source

# Sync to a remote server over SSH
rsync -avz -e "ssh -i ~/.ssh/backup_key" /data/ backup@remote:/backups/server01/

# Exclude patterns
rsync -avz --delete \
  --exclude='*.tmp' \
  --exclude='*.log' \
  --exclude='.cache/' \
  --exclude='node_modules/' \
  /data/ /backup/data/

# Use an exclude file for complex patterns
rsync -avz --delete --exclude-from=/etc/backup-excludes.txt /data/ /backup/data/

# Dry run (preview what would change)
rsync -avzn --delete /data/ /backup/data/

# Limit bandwidth to 50 MB/s and show progress
rsync -avz --bwlimit=50000 --progress /data/ backup@remote:/backups/
```

### Incremental Backups with Hard Links

```bash
# Incremental: unchanged files hard-linked to previous backup (saves space)
rsync -avz --delete \
  --link-dest=/backup/daily/latest \
  /data/ /backup/daily/$(date +%Y-%m-%d)/

# Update the 'latest' symlink
ln -snf /backup/daily/$(date +%Y-%m-%d) /backup/daily/latest

# Remove backups older than 30 days
find /backup/daily -maxdepth 1 -type d -name "20*" -mtime +30 -exec rm -rf {} \;
```

## Restic Backup

### Installation

```bash
# Debian / Ubuntu
apt install -y restic

# RHEL / CentOS
dnf install -y restic

# Alternatively obtain a pinned release for the actual OS/architecture from
# https://github.com/restic/restic/releases and verify its published checksums
# and signature before installing it. Do not mix latest/ URLs with old filenames.

# Verify installation
restic version
```

### Initialize a Repository

```bash
# Local repository
restic init --repo /backup/restic-repo

# AWS S3 backend
export AWS_ACCESS_KEY_ID="AKIAEXAMPLE"
export AWS_SECRET_ACCESS_KEY="secretkey"
restic init --repo s3:s3.amazonaws.com/my-backup-bucket

# S3-compatible (MinIO)
export AWS_ACCESS_KEY_ID="minioadmin"
export AWS_SECRET_ACCESS_KEY="miniosecret"
restic init --repo s3:https://minio.example.com:9000/backup-bucket

# Backblaze B2 backend
export B2_ACCOUNT_ID="accountid"
export B2_ACCOUNT_KEY="accountkey"
restic init --repo b2:my-backup-bucket:server01

# SFTP backend
restic init --repo sftp:backup@remote:/backups/server01

# Restic will prompt for a repository password -- store it securely
# Use a password file for automation
umask 077
read -r -s -p "Repository password: " RESTIC_NEW_PASSWORD
printf '%s\n' "$RESTIC_NEW_PASSWORD" > /etc/restic/password.txt
unset RESTIC_NEW_PASSWORD
chmod 600 /etc/restic/password.txt
```

### Backup Operations

```bash
# Basic backup
restic backup /data --repo /backup/restic-repo --password-file /etc/restic/password.txt

# Backup multiple directories
restic backup /data /etc \
  --repo s3:s3.amazonaws.com/my-backup-bucket \
  --password-file /etc/restic/password.txt

# Backup with exclusions
restic backup /data \
  --exclude='*.tmp' \
  --exclude='*.log' \
  --exclu
