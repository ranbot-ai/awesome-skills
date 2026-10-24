---
name: cloudflare-zero-trust
description: Protect internal apps with Cloudflare Access, device posture, and Zero Trust policies. 
category: Development & Code Tools
source: antigravity
tags: [api, ai, agent, llm, automation, template, image, security, docker, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudflare-zero-trust
---


# Cloudflare Zero Trust

Secure access to internal services without VPNs using Cloudflare's Zero Trust platform (Access, Tunnel, Gateway, and WARP).

## When to Use

- Replacing VPN access to internal web applications, SSH, or RDP.
- Enforcing identity-aware access policies on internal tools (dashboards, admin panels).
- Exposing on-premises or private-network services securely to remote teams.
- Filtering DNS traffic to block malware, phishing, and shadow IT.
- Enforcing device posture checks (managed devices, OS version, disk encryption).

## Prerequisites

- Cloudflare account with Zero Trust plan (free tier supports up to 50 users).
- A domain on Cloudflare (for Access application hostnames).
- Identity provider configured (Google Workspace, Okta, Azure AD/Entra ID, GitHub).
- `cloudflared` CLI installed on the server hosting internal services.

```bash
# Install cloudflared
# macOS
brew install cloudflared

# Debian/Ubuntu
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install -y cloudflared

# Docker
docker pull cloudflare/cloudflared:latest
```

## Cloudflare Tunnel Setup

Tunnels create encrypted outbound connections from your infrastructure to Cloudflare's edge, eliminating the need to open inbound ports.

### Create and Configure a Tunnel

```bash
# Authenticate with Cloudflare
cloudflared tunnel login

# Create a named tunnel
cloudflared tunnel create internal-apps

# This creates credentials at ~/.cloudflared/<TUNNEL_ID>.json

# List tunnels
cloudflared tunnel list

# Route DNS to the tunnel (creates a CNAME record)
cloudflared tunnel route dns internal-apps grafana.example.com
cloudflared tunnel route dns internal-apps wiki.example.com
cloudflared tunnel route dns internal-apps ssh.example.com
```

### Tunnel Configuration File

```yaml
# ~/.cloudflared/config.yml
tunnel: <TUNNEL_ID>
credentials-file: /home/deploy/.cloudflared/<TUNNEL_ID>.json

ingress:
  # Grafana dashboard
  - hostname: grafana.example.com
    service: http://localhost:3000

  # Internal wiki
  - hostname: wiki.example.com
    service: http://localhost:8080

  # SSH access via browser
  - hostname: ssh.example.com
    service: ssh://localhost:22

  # Catch-all — required as the last rule
  - service: http_status:404
```

Private CIDRs are routes, not HTTP origin URLs. Configure a Tunnel CIDR route and authorized Cloudflare One Client/split-tunnel policy through the [private-network guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/cloudflared/connect-cidr/).

### Run the Tunnel

```bash
# Run in foreground (for testing)
cloudflared tunnel run internal-apps

# Install as a systemd service
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared

# Or run via Docker
docker run -d --name cloudflared \
  --restart unless-stopped \
  -v /home/deploy/.cloudflared:/etc/cloudflared \
  cloudflare/cloudflared:latest \
  tunnel run internal-apps
```

### Docker Compose with Tunnel

```yaml
# docker-compose.yml
version: "3.8"
services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel run
    environment:
      - TUNNEL_TOKEN=${TUNNEL_TOKEN}
    networks:
      - internal

  grafana:
    image: grafana/grafana:latest
    networks:
      - internal

  wiki:
    image: requarks/wiki:2
    networks:
      - internal

networks:
  internal:
    driver: bridge
```

## Access Policies

A Tunnel does not itself add user authentication. Configure and test Access before exposing the hostname: unauthorized requests must fail, authorized identities must succeed, and direct origin access must be constrained. Protect generated service-token responses and pass secret headers through protected stdin/config rather than logged process arguments. Verify current plans, DNS endpoints, browser-SSH requirements and policy schemas; static examples may drift. See [Access policy evaluation](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/).

Access policies control who can reach applications behind Cloudflare.

### Create an Access Application

```bash
# Via API — create a self-hosted application
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/access/apps" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Grafana",
    "domain": "grafana.example.com",
    "type": "self_hosted",
    "session_duration": "12h",
    "auto_redirect_to_identity": true,
    "allowed_idps": ["<IDP_UUID>"]
  }'
```

### Policy Types and Examples

```bash
# Allow policy — members of the engineering group
curl -X POST "https://api.cloudflare.com/client/v4/acc
