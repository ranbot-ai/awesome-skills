---
name: Linux Production Shell Scripts
description: This skill should be used when the user asks to "create bash scripts", "automate Linux tasks", "monitor system resources", "backup files", "manage users", or "write production shell scripts". It provi
category: Security & Systems
source: antigravity
tags: [ai, automation, workflow, template, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/linux-shell-scripting
---


# Linux Production Shell Scripts

## Purpose

Provide production-ready shell script templates for common Linux system administration tasks including backups, monitoring, user management, log analysis, and automation. These scripts serve as building blocks for security operations and penetration testing environments.

## Prerequisites

### Required Environment
- Linux/Unix system (bash shell)
- Appropriate permissions for tasks
- Required utilities installed (rsync, openssl, etc.)

### Required Knowledge
- Basic bash scripting
- Linux file system structure
- System administration concepts

## Outputs and Deliverables

1. **Backup Solutions** - Automated file and database backups
2. **Monitoring Scripts** - Resource usage tracking
3. **Automation Tools** - Scheduled task execution
4. **Security Scripts** - Password management, encryption

## Core Workflow

### Phase 1: File Backup Scripts

**Basic Directory Backup**
```bash
#!/bin/bash
backup_dir="/path/to/backup"
source_dir="/path/to/source"

# Create a timestamped backup of the source directory
tar -czf "$backup_dir/backup_$(date +%Y%m%d_%H%M%S).tar.gz" "$source_dir"
echo "Backup completed: backup_$(date +%Y%m%d_%H%M%S).tar.gz"
```

**Remote Server Backup**
```bash
#!/bin/bash
source_dir="/path/to/source"
remote_server="user@remoteserver:/path/to/backup"

# Backup files/directories to a remote server using rsync
rsync -avz --progress "$source_dir" "$remote_server"
echo "Files backed up to remote server."
```

**Backup Rotation Script**
```bash
#!/bin/bash
backup_dir="/path/to/backups"
max_backups=5

# Rotate backups by deleting the oldest if more than max_backups
while [ $(ls -1 "$backup_dir" | wc -l) -gt "$max_backups" ]; do
    oldest_backup=$(ls -1t "$backup_dir" | tail -n 1)
    rm -r "$backup_dir/$oldest_backup"
    echo "Removed old backup: $oldest_backup"
done
echo "Backup rotation completed."
```

**Database Backup Script**
```bash
#!/bin/bash
database_name="your_database"
db_user="username"
db_pass="password"
output_file="database_backup_$(date +%Y%m%d).sql"

# Perform database backup using mysqldump
mysqldump -u "$db_user" -p"$db_pass" "$database_name" > "$output_file"
gzip "$output_file"
echo "Database backup created: $output_file.gz"
```

### Phase 2: System Monitoring Scripts

**CPU Usage Monitor**
```bash
#!/bin/bash
threshold=90

# Monitor CPU usage and trigger alert if threshold exceeded
cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)

if [ "$cpu_usage" -gt "$threshold" ]; then
    echo "ALERT: High CPU usage detected: $cpu_usage%"
    # Add notification logic (email, slack, etc.)
    # mail -s "CPU Alert" admin@example.com <<< "CPU usage: $cpu_usage%"
fi
```

**Disk Space Monitor**
```bash
#!/bin/bash
threshold=90
partition="/dev/sda1"

# Monitor disk usage and trigger alert if threshold exceeded
disk_usage=$(df -h | grep "$partition" | awk '{print $5}' | cut -d% -f1)

if [ "$disk_usage" -gt "$threshold" ]; then
    echo "ALERT: High disk usage detected: $disk_usage%"
    # Add alert/notification logic here
fi
```

**CPU Usage Logger**
```bash
#!/bin/bash
output_file="cpu_usage_log.txt"

# Log current CPU usage to a file with timestamp
timestamp=$(date '+%Y-%m-%d %H:%M:%S')
cpu_usage=$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d. -f1)
echo "$timestamp - CPU Usage: $cpu_usage%" >> "$output_file"
echo "CPU usage logged."
```

**System Health Check**
```bash
#!/bin/bash
output_file="system_health_check.txt"

# Perform system health check and save results to a file
{
    echo "System Health Check - $(date)"
    echo "================================"
    echo ""
    echo "Uptime:"
    uptime
    echo ""
    echo "Load Average:"
    cat /proc/loadavg
    echo ""
    echo "Memory Usage:"
    free -h
    echo ""
    echo "Disk Usage:"
    df -h
    echo ""
    echo "Top Processes:"
    ps aux --sort=-%cpu | head -10
} > "$output_file"

echo "System health check saved to $output_file"
```

### Phase 3: User Management Scripts

**User Account Creation**
```bash
#!/bin/bash
username="newuser"

# Check if user exists; if not, create new user
if id "$username" &>/dev/null; then
    echo "User $username already exists."
else
    useradd -m -s /bin/bash "$username"
    echo "User $username created."
    
    # Set password interactively
    passwd "$username"
fi
```

**Password Expiry Checker**
```bash
#!/bin/bash
output_file="password_expiry_report.txt"

# Check password expiry for users with bash shell
echo "Password Expiry Report - $(date)" > "$output_file"
echo "=================================" >> "$output_file"

IFS=$'\n'
for user in $(grep "/bin/bash" /etc/passwd | cut -d: -f1); do
    password_expires=$(chage -l "$user" 2>/dev/null | grep "Password expires" | awk -F: '{print $2}')
    echo "User: $user - Password Expires: $password_expires" >> "$output_file"
done
unset IFS

echo "Password expiry report saved to $output_file"
```

### Phase 4: Security Scripts

**Password Generator**
```bash
#!/bin/bash
length=${1
