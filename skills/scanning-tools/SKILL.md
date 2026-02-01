---
name: Security Scanning Tools
description: This skill should be used when the user asks to "perform vulnerability scanning", "scan networks for open ports", "assess web application security", "scan wireless networks", "detect malware", "check 
category: Security & Systems
source: antigravity
tags: [pdf, api, ai, automation, workflow, template, document, security, vulnerability, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/scanning-tools
---


# Security Scanning Tools

## Purpose

Master essential security scanning tools for network discovery, vulnerability assessment, web application testing, wireless security, and compliance validation. This skill covers tool selection, configuration, and practical usage across different scanning categories.

## Prerequisites

### Required Environment
- Linux-based system (Kali Linux recommended)
- Network access to target systems
- Proper authorization for scanning activities

### Required Knowledge
- Basic networking concepts (TCP/IP, ports, protocols)
- Understanding of common vulnerabilities
- Familiarity with command-line interfaces

## Outputs and Deliverables

1. **Network Discovery Reports** - Identified hosts, ports, and services
2. **Vulnerability Assessment Reports** - CVEs, misconfigurations, risk ratings
3. **Web Application Security Reports** - OWASP Top 10 findings
4. **Compliance Reports** - CIS benchmarks, PCI-DSS, HIPAA checks

## Core Workflow

### Phase 1: Network Scanning Tools

#### Nmap (Network Mapper)

Primary tool for network discovery and security auditing:

```bash
# Host discovery
nmap -sn 192.168.1.0/24              # Ping scan (no port scan)
nmap -sL 192.168.1.0/24              # List scan (DNS resolution)
nmap -Pn 192.168.1.100               # Skip host discovery

# Port scanning techniques
nmap -sS 192.168.1.100               # TCP SYN scan (stealth)
nmap -sT 192.168.1.100               # TCP connect scan
nmap -sU 192.168.1.100               # UDP scan
nmap -sA 192.168.1.100               # ACK scan (firewall detection)

# Port specification
nmap -p 80,443 192.168.1.100         # Specific ports
nmap -p- 192.168.1.100               # All 65535 ports
nmap -p 1-1000 192.168.1.100         # Port range
nmap --top-ports 100 192.168.1.100   # Top 100 common ports

# Service and OS detection
nmap -sV 192.168.1.100               # Service version detection
nmap -O 192.168.1.100                # OS detection
nmap -A 192.168.1.100                # Aggressive (OS, version, scripts)

# Timing and performance
nmap -T0 192.168.1.100               # Paranoid (slowest, IDS evasion)
nmap -T4 192.168.1.100               # Aggressive (faster)
nmap -T5 192.168.1.100               # Insane (fastest)

# NSE Scripts
nmap --script=vuln 192.168.1.100     # Vulnerability scripts
nmap --script=http-enum 192.168.1.100  # Web enumeration
nmap --script=smb-vuln* 192.168.1.100  # SMB vulnerabilities
nmap --script=default 192.168.1.100  # Default script set

# Output formats
nmap -oN scan.txt 192.168.1.100      # Normal output
nmap -oX scan.xml 192.168.1.100      # XML output
nmap -oG scan.gnmap 192.168.1.100    # Grepable output
nmap -oA scan 192.168.1.100          # All formats
```

#### Masscan

High-speed port scanning for large networks:

```bash
# Basic scanning
masscan -p80 192.168.1.0/24 --rate=1000
masscan -p80,443,8080 192.168.1.0/24 --rate=10000

# Full port range
masscan -p0-65535 192.168.1.0/24 --rate=5000

# Large-scale scanning
masscan 0.0.0.0/0 -p443 --rate=100000 --excludefile exclude.txt

# Output formats
masscan -p80 192.168.1.0/24 -oG results.gnmap
masscan -p80 192.168.1.0/24 -oJ results.json
masscan -p80 192.168.1.0/24 -oX results.xml

# Banner grabbing
masscan -p80 192.168.1.0/24 --banners
```

### Phase 2: Vulnerability Scanning Tools

#### Nessus

Enterprise-grade vulnerability assessment:

```bash
# Start Nessus service
sudo systemctl start nessusd

# Access web interface
# https://localhost:8834

# Command-line (nessuscli)
nessuscli scan --create --name "Internal Scan" --targets 192.168.1.0/24
nessuscli scan --list
nessuscli scan --launch <scan_id>
nessuscli report --format pdf --output report.pdf <scan_id>
```

Key Nessus features:
- Comprehensive CVE detection
- Compliance checks (PCI-DSS, HIPAA, CIS)
- Custom scan templates
- Credentialed scanning for deeper analysis
- Regular plugin updates

#### OpenVAS (Greenbone)

Open-source vulnerability scanning:

```bash
# Install OpenVAS
sudo apt install openvas
sudo gvm-setup

# Start services
sudo gvm-start

# Access web interface (Greenbone Security Assistant)
# https://localhost:9392

# Command-line operations
gvm-cli socket --xml "<get_version/>"
gvm-cli socket --xml "<get_tasks/>"

# Create and run scan
gvm-cli socket --xml '
<create_target>
  <name>Test Target</name>
  <hosts>192.168.1.0/24</hosts>
</create_target>'
```

### Phase 3: Web Application Scanning Tools

#### Burp Suite

Comprehensive web application testing:

```
# Proxy configuration
1. Set browser proxy to 127.0.0.1:8080
2. Import Burp CA certificate for HTTPS
3. Add target to scope

# Key modules:
- Proxy: Intercept and modify requests
- Spider: Crawl web applications
- Scanner: Automated vulnerability detection
- Intruder: Automated attacks (fuzzing, brute-force)
- Repeater: Manual request manipulation
- Decoder: Encode/decode data
- Comparer: Compare responses
```

Core testing workflow:
1. Configure proxy and scope
2. Spider the application
3. Analyze sitemap
4. R
