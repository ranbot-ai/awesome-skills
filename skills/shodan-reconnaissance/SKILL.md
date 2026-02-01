---
name: Shodan Reconnaissance and Pentesting
description: This skill should be used when the user asks to "search for exposed devices on the internet," "perform Shodan reconnaissance," "find vulnerable services using Shodan," "scan IP ranges with Shodan," or
category: Security & Systems
source: antigravity
tags: [python, api, ai, automation, workflow, document, pentest, vulnerability, docker, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/shodan-reconnaissance
---


# Shodan Reconnaissance and Pentesting

## Purpose

Provide systematic methodologies for leveraging Shodan as a reconnaissance tool during penetration testing engagements. This skill covers the Shodan web interface, command-line interface (CLI), REST API, search filters, on-demand scanning, and network monitoring capabilities for discovering exposed services, vulnerable systems, and IoT devices.

## Inputs / Prerequisites

- **Shodan Account**: Free or paid account at shodan.io
- **API Key**: Obtained from Shodan account dashboard
- **Target Information**: IP addresses, domains, or network ranges to investigate
- **Shodan CLI**: Python-based command-line tool installed
- **Authorization**: Written permission for reconnaissance on target networks

## Outputs / Deliverables

- **Asset Inventory**: List of discovered hosts, ports, and services
- **Vulnerability Report**: Identified CVEs and exposed vulnerable services
- **Banner Data**: Service banners revealing software versions
- **Network Mapping**: Geographic and organizational distribution of assets
- **Screenshot Gallery**: Visual reconnaissance of exposed interfaces
- **Exported Data**: JSON/CSV files for further analysis

## Core Workflow

### 1. Setup and Configuration

#### Install Shodan CLI
```bash
# Using pip
pip install shodan

# Or easy_install
easy_install shodan

# On BlackArch/Arch Linux
sudo pacman -S python-shodan
```

#### Initialize API Key
```bash
# Set your API key
shodan init YOUR_API_KEY

# Verify setup
shodan info
# Output: Query credits available: 100
#         Scan credits available: 100
```

#### Check Account Status
```bash
# View credits and plan info
shodan info

# Check your external IP
shodan myip

# Check CLI version
shodan version
```

### 2. Basic Host Reconnaissance

#### Query Single Host
```bash
# Get all information about an IP
shodan host 1.1.1.1

# Example output:
# 1.1.1.1
# Hostnames: one.one.one.one
# Country: Australia
# Organization: Mountain View Communications
# Number of open ports: 3
# Ports:
#   53/udp
#   80/tcp
#   443/tcp
```

#### Check if Host is Honeypot
```bash
# Get honeypot probability score
shodan honeyscore 192.168.1.100

# Output: Not a honeypot
#         Score: 0.3
```

### 3. Search Queries

#### Basic Search (Free)
```bash
# Simple keyword search (no credits consumed)
shodan search apache

# Specify output fields
shodan search --fields ip_str,port,os smb
```

#### Filtered Search (1 Credit)
```bash
# Product-specific search
shodan search product:mongodb

# Search with multiple filters
shodan search product:nginx country:US city:"New York"
```

#### Count Results
```bash
# Get result count without consuming credits
shodan count openssh
# Output: 23128

shodan count openssh 7
# Output: 219
```

#### Download Results
```bash
# Download 1000 results (default)
shodan download results.json.gz "apache country:US"

# Download specific number of results
shodan download --limit 5000 results.json.gz "nginx"

# Download all available results
shodan download --limit -1 all_results.json.gz "query"
```

#### Parse Downloaded Data
```bash
# Extract specific fields from downloaded data
shodan parse --fields ip_str,port,hostnames results.json.gz

# Filter by specific criteria
shodan parse --fields location.country_code3,ip_str -f port:22 results.json.gz

# Export to CSV format
shodan parse --fields ip_str,port,org --separator , results.json.gz > results.csv
```

### 4. Search Filters Reference

#### Network Filters
```
ip:1.2.3.4                  # Specific IP address
net:192.168.0.0/24          # Network range (CIDR)
hostname:example.com        # Hostname contains
port:22                     # Specific port
asn:AS15169                 # Autonomous System Number
```

#### Geographic Filters
```
country:US                  # Two-letter country code
country:"United States"     # Full country name
city:"San Francisco"        # City name
state:CA                    # State/region
postal:94102                # Postal/ZIP code
geo:37.7,-122.4             # Lat/long coordinates
```

#### Organization Filters
```
org:"Google"                # Organization name
isp:"Comcast"               # ISP name
```

#### Service/Product Filters
```
product:nginx               # Software product
version:1.14.0              # Software version
os:"Windows Server 2019"    # Operating system
http.title:"Dashboard"      # HTTP page title
http.html:"login"           # HTML content
http.status:200             # HTTP status code
ssl.cert.subject.cn:*.example.com  # SSL certificate
ssl:true                    # Has SSL enabled
```

#### Vulnerability Filters
```
vuln:CVE-2019-0708          # Specific CVE
has_vuln:true               # Has any vulnerability
```

#### Screenshot Filters
```
has_screenshot:true         # Has screenshot available
screenshot.label:webcam     # Screenshot type
```

### 5. On-Demand Scanning

#### Submit Scan
```bash
# Scan single IP (1 credit per IP)
shodan scan submit 192.168.1.100

# Scan with verbose output (s
