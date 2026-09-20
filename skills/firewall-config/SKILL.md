---
name: firewall-config
description: Configure iptables, nftables, and cloud firewalls. Implement network segmentation and traffic filtering. Use when securing network perimeters or implementing security zones. 
category: Document Processing
source: antigravity
tags: [node, ai, agent, template, document, security, docker, aws, gcp, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/firewall-config
---


# Firewall Configuration

Configure host-based and cloud firewalls for network security.

## When to Use This Skill

Use this skill when:
- Setting up a new server and need to restrict network access
- Implementing network segmentation between application tiers
- Configuring cloud security groups for AWS, GCP, or Azure resources
- Migrating from iptables to nftables
- Auditing existing firewall rules for compliance
- Responding to a security incident requiring emergency network blocks

## Prerequisites

- Root or sudo access on Linux hosts
- AWS CLI configured for cloud security groups
- Understanding of TCP/IP, ports, and protocols
- Network diagram showing required traffic flows

## iptables

### Basic Setup with Default Deny

```bash
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# Default policies - deny all inbound, allow outbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Allow SSH (restrict to management subnet)
iptables -A INPUT -p tcp --dport 22 -s 10.0.100.0/24 -j ACCEPT

# Allow HTTP/HTTPS from anywhere
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow ICMP (ping) with rate limiting
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT

# Log dropped packets (rate limited to avoid log flooding)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4

# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

### Anti-DDoS Rules

```bash
# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Limit new connections per source IP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT

# Block port scanning (detect TCP flags abuse)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
```

### Application-Specific Rules

```bash
# Web server with database backend
# Allow app servers to reach database (port 5432)
iptables -A INPUT -p tcp --dport 5432 -s 10.0.1.0/24 -j ACCEPT

# Allow monitoring (Prometheus node exporter)
iptables -A INPUT -p tcp --dport 9100 -s 10.0.200.0/24 -j ACCEPT

# DNS resolution
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -j ACCEPT

# NTP
iptables -A INPUT -p udp --sport 123 -j ACCEPT

# Block specific IP (incident response)
iptables -I INPUT 1 -s 203.0.113.50 -j DROP
```

## UFW (Uncomplicated Firewall)

```bash
# Enable UFW with default deny
ufw default deny incoming
ufw default allow outgoing
ufw enable

# Allow SSH from management network
ufw allow from 10.0.100.0/24 to any port 22 proto tcp

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow specific application profile
ufw allow 'Nginx Full'

# Rate limit SSH (max 6 connections in 30 seconds)
ufw limit ssh

# Allow port range
ufw allow 8000:8080/tcp

# Deny specific IP
ufw deny from 203.0.113.50

# Check status
ufw status verbose
ufw status numbered

# Delete a rule by number
ufw delete 3

# Application profiles
ufw app list
ufw app info 'Nginx Full'
```

## nftables

### Complete Server Configuration

```bash
#!/usr/sbin/nft -f
flush ruleset

# Define variables
define LAN = 10.0.0.0/16
define MGMT = 10.0.100.0/24
define MONITOR = 10.0.200.0/24

table inet filter {
  # Rate limiting set
  set rate_limit {
    type ipv4_addr
    flags dynamic,timeout
    timeout 1m
  }

  chain input {
    type filter hook input priority 0; policy drop;

    # Connection tracking
    ct state established,related accept
    ct state invalid drop

    # Loopback
    iif "lo" accept

    # ICMP and ICMPv6
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
    ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert } accept

    # SSH from management only
    tcp dport 22 ip saddr $MGMT accept

    # HTTP/HTTPS from anywhere
    tcp dport { 80, 443 } accept

    # Prometheus metrics from monitoring subnet
    tcp dport 9100 ip saddr $MONITOR accept

    # Rate limit new connections
    tcp flags syn limit rate over 25/second burst 50 packets drop

    # Log dropped traffic
    log prefix "nft-drop: " level warn limit rate 5/minute
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;

    # Optiona
