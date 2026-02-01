---
name: Ethical Hacking Methodology
description: This skill should be used when the user asks to "learn ethical hacking", "understand penetration testing lifecycle", "perform reconnaissance", "conduct security scanning", "exploit vulnerabilities", o
category: Security & Systems
source: antigravity
tags: [pdf, api, ai, workflow, template, document, security, hacking, vulnerability, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ethical-hacking-methodology
---


# Ethical Hacking Methodology

## Purpose

Master the complete penetration testing lifecycle from reconnaissance through reporting. This skill covers the five stages of ethical hacking methodology, essential tools, attack techniques, and professional reporting for authorized security assessments.

## Prerequisites

### Required Environment
- Kali Linux installed (persistent or live)
- Network access to authorized targets
- Written authorization from system owner

### Required Knowledge
- Basic networking concepts
- Linux command-line proficiency
- Understanding of web technologies
- Familiarity with security concepts

## Outputs and Deliverables

1. **Reconnaissance Report** - Target information gathered
2. **Vulnerability Assessment** - Identified weaknesses
3. **Exploitation Evidence** - Proof of concept attacks
4. **Final Report** - Executive and technical findings

## Core Workflow

### Phase 1: Understanding Hacker Types

Classification of security professionals:

**White Hat Hackers (Ethical Hackers)**
- Authorized security professionals
- Conduct penetration testing with permission
- Goal: Identify and fix vulnerabilities
- Also known as: penetration testers, security consultants

**Black Hat Hackers (Malicious)**
- Unauthorized system intrusions
- Motivated by profit, revenge, or notoriety
- Goal: Steal data, cause damage
- Also known as: crackers, criminal hackers

**Grey Hat Hackers (Hybrid)**
- May cross ethical boundaries
- Not malicious but may break rules
- Often disclose vulnerabilities publicly
- Mixed motivations

**Other Classifications**
- **Script Kiddies**: Use pre-made tools without understanding
- **Hacktivists**: Politically or socially motivated
- **Nation State**: Government-sponsored operatives
- **Coders**: Develop tools and exploits

### Phase 2: Reconnaissance

Gather information without direct system interaction:

**Passive Reconnaissance**
```bash
# WHOIS lookup
whois target.com

# DNS enumeration
nslookup target.com
dig target.com ANY
dig target.com MX
dig target.com NS

# Subdomain discovery
dnsrecon -d target.com

# Email harvesting
theHarvester -d target.com -b all
```

**Google Hacking (OSINT)**
```
# Find exposed files
site:target.com filetype:pdf
site:target.com filetype:xls
site:target.com filetype:doc

# Find login pages
site:target.com inurl:login
site:target.com inurl:admin

# Find directory listings
site:target.com intitle:"index of"

# Find configuration files
site:target.com filetype:config
site:target.com filetype:env
```

**Google Hacking Database Categories:**
- Files containing passwords
- Sensitive directories
- Web server detection
- Vulnerable servers
- Error messages
- Login portals

**Social Media Reconnaissance**
- LinkedIn: Organizational charts, technologies used
- Twitter: Company announcements, employee info
- Facebook: Personal information, relationships
- Job postings: Technology stack revelations

### Phase 3: Scanning

Active enumeration of target systems:

**Host Discovery**
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
arp-scan -l

# Discover live hosts
nmap -sP 192.168.1.0/24
```

**Port Scanning**
```bash
# TCP SYN scan (stealth)
nmap -sS target.com

# Full TCP connect scan
nmap -sT target.com

# UDP scan
nmap -sU target.com

# All ports scan
nmap -p- target.com

# Top 1000 ports with service detection
nmap -sV target.com

# Aggressive scan (OS, version, scripts)
nmap -A target.com
```

**Service Enumeration**
```bash
# Specific service scripts
nmap --script=http-enum target.com
nmap --script=smb-enum-shares target.com
nmap --script=ftp-anon target.com

# Vulnerability scanning
nmap --script=vuln target.com
```

**Common Port Reference**
| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | File transfer |
| 22 | SSH | Secure shell |
| 23 | Telnet | Unencrypted remote |
| 25 | SMTP | Email |
| 53 | DNS | Name resolution |
| 80 | HTTP | Web |
| 443 | HTTPS | Secure web |
| 445 | SMB | Windows shares |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote desktop |

### Phase 4: Vulnerability Analysis

Identify exploitable weaknesses:

**Automated Scanning**
```bash
# Nikto web scanner
nikto -h http://target.com

# OpenVAS (command line)
omp -u admin -w password --xml="<get_tasks/>"

# Nessus (via API)
nessuscli scan --target target.com
```

**Web Application Testing (OWASP)**
- SQL Injection
- Cross-Site Scripting (XSS)
- Broken Authentication
- Security Misconfiguration
- Sensitive Data Exposure
- XML External Entities (XXE)
- Broken Access Control
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

**Manual Techniques**
```bash
# Directory brute forcing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# Web technology fingerprinting
whatweb target.com
```

### Phase 5: Exploitation

Actively exploit discovered vulnerabilities:

**M
