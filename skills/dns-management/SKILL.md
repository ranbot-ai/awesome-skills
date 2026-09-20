---
name: dns-management
description: Configure DNS zones and records. Manage Route53, Cloud DNS, and self-hosted DNS. Use when setting up DNS infrastructure. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, template, security, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dns-management
---


# DNS Management

Configure and manage DNS zones, records, and resolution for production infrastructure.

## When to Use

- Setting up domains for web applications, APIs, and email.
- Migrating DNS providers or consolidating zones.
- Configuring DNS for CDN, load balancers, and cloud services.
- Troubleshooting resolution failures, propagation delays, or misconfigurations.
- Implementing DNSSEC, SPF, DKIM, and DMARC for email security.

## Prerequisites

- Domain registered with a registrar (Namecheap, Route53, Google Domains, Cloudflare).
- Access to DNS provider dashboard or API.
- AWS CLI configured (for Route53 examples).
- `dig` and `nslookup` available locally (included in most OS installs).

## DNS Record Types Reference

| Type  | Purpose | Example Value |
|-------|---------|---------------|
| A     | IPv4 address | `93.184.216.34` |
| AAAA  | IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | Alias to another domain | `www.example.com -> example.com` |
| MX    | Mail server with priority | `10 mail.example.com` |
| TXT   | Arbitrary text (SPF, DKIM, verification) | `v=spf1 include:_spf.google.com ~all` |
| NS    | Authoritative name servers | `ns1.example.com` |
| SRV   | Service location (host, port, priority) | `10 5 5060 sip.example.com` |
| CAA   | Certificate Authority Authorization | `0 issue "letsencrypt.org"` |
| PTR   | Reverse DNS lookup | `34.216.184.93.in-addr.arpa` |

## AWS Route 53

### Hosted Zone Management

```bash
# Create a hosted zone
aws route53 create-hosted-zone \
  --name example.com \
  --caller-reference "$(date +%s)"

# List hosted zones
aws route53 list-hosted-zones

# Get name servers for a zone (update at your registrar)
aws route53 get-hosted-zone --id Z1234567890ABC \
  --query 'DelegationSet.NameServers'
```

### Create and Manage Records

```bash
# Create an A record
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "app.example.com",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "93.184.216.34"}]
      }
    }]
  }'

# Create a CNAME record
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "www.example.com",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "example.com"}]
      }
    }]
  }'

# Create an alias record (no TTL, Route53-specific)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "example.com",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "Z2FDTNDATAQYW2",
          "DNSName": "d1234567890.cloudfront.net",
          "EvaluateTargetHealth": false
        }
      }
    }]
  }'

# List records in a zone
aws route53 list-resource-record-sets --hosted-zone-id Z1234567890ABC

# Delete a record (Action: DELETE with exact match)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "old.example.com",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "1.2.3.4"}]
      }
    }]
  }'
```

### Route 53 Health Checks

```bash
# Create a health check
aws route53 create-health-check --caller-reference "$(date +%s)" \
  --health-check-config '{
    "IPAddress": "93.184.216.34",
    "Port": 443,
    "Type": "HTTPS",
    "ResourcePath": "/health",
    "RequestInterval": 30,
    "FailureThreshold": 3
  }'
```

## Cloudflare DNS

### Manage Records via API

```bash
# Get zone ID
ZONE_ID=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq -r '.result[0].id')

# Create an A record (proxied through Cloudflare)
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"A","name":"app","content":"93.184.216.34","proxied":true,"ttl":1}'

# Create a CNAME record (DNS only, not proxied)
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -d '{"type":"CNAME","name":"docs","content":"docs.readthedocs.io","proxied":false,"ttl":3600}'

# List all records
curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result[] | {name, type, content, proxied}'

# Delete a record
curl -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer $CF_API_TOKEN"
```

## Terraform DNS Management

### Route 53 with Terraform

```hcl
# dns.tf
