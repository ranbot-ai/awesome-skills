---
name: agentmail
description: Email infrastructure for AI agents. Create accounts, send/receive emails, manage webhooks, and check karma balance via the AgentMail API. 
category: AI & Agents
source: antigravity
tags: [typescript, api, ai, agent, automation, security, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agentmail
---


# AgentMail — Email for AI Agents

AgentMail gives AI agents real email addresses (`@theagentmail.net`) with a REST API. Agents can send and receive email, sign up for services (GitHub, AWS, Slack, etc.), and get verification codes. A karma system prevents spam and keeps the shared domain's reputation high.

Base URL: `https://api.theagentmail.net`

## When to Use
- An AI agent needs a real inbox/outbox for signups, verification flows, or transactional communication.
- You need to provision AgentMail accounts, send messages, read inbox contents, or register inbound webhooks.
- You need to monitor karma usage or wire email events into agent automation.

## Quick start

All requests require `Authorization: Bearer am_...` header (API key from dashboard).

### Create an email account (-10 karma)

```bash
curl -X POST https://api.theagentmail.net/v1/accounts \
  -H "Authorization: Bearer am_..." \
  -H "Content-Type: application/json" \
  -d '{"address": "my-agent@theagentmail.net"}'
```

Response: `{"data": {"id": "...", "address": "my-agent@theagentmail.net", "displayName": null, "createdAt": 123}}`

### Send email (-1 karma)

```bash
curl -X POST https://api.theagentmail.net/v1/accounts/{accountId}/messages \
  -H "Authorization: Bearer am_..." \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "subject": "Hello from my agent",
    "text": "Plain text body",
    "html": "<p>Optional HTML body</p>"
  }'
```

Optional fields: `cc`, `bcc` (string arrays), `inReplyTo`, `references` (strings for threading), `attachments` (array of `{filename, contentType, content}` where content is base64).

### Read inbox

```bash
# List messages
curl https://api.theagentmail.net/v1/accounts/{accountId}/messages \
  -H "Authorization: Bearer am_..."

# Get full message (with body and attachments)
curl https://api.theagentmail.net/v1/accounts/{accountId}/messages/{messageId} \
  -H "Authorization: Bearer am_..."
```

### Check karma

```bash
curl https://api.theagentmail.net/v1/karma \
  -H "Authorization: Bearer am_..."
```

Response: `{"data": {"balance": 90, "events": [...]}}`

### Register webhook (real-time inbound)

```bash
curl -X POST https://api.theagentmail.net/v1/accounts/{accountId}/webhooks \
  -H "Authorization: Bearer am_..." \
  -H "Content-Type: application/json" \
  -d '{"url": "https://my-agent.example.com/inbox"}'
```

Webhook deliveries include two security headers:
- `X-AgentMail-Signature` -- HMAC-SHA256 hex digest of the request body, signed with the webhook secret
- `X-AgentMail-Timestamp` -- millisecond timestamp of when the delivery was sent

Verify the signature and reject requests with timestamps older than 5 minutes to prevent replay attacks:

```typescript
import { createHmac } from "crypto";

const verifyWebhook = (body: string, signature: string, timestamp: string, secret: string) => {
  if (Date.now() - Number(timestamp) > 5 * 60 * 1000) return false;
  return createHmac("sha256", secret).update(body).digest("hex") === signature;
};
```

### Download attachment

```bash
curl https://api.theagentmail.net/v1/accounts/{accountId}/messages/{messageId}/attachments/{attachmentId} \
  -H "Authorization: Bearer am_..."
```

Returns `{"data": {"url": "https://signed-download-url..."}}`.

## Full API reference

| Method | Path | Description | Karma |
|--------|------|-------------|-------|
| POST | `/v1/accounts` | Create email account | -10 |
| GET | `/v1/accounts` | List all accounts | |
| GET | `/v1/accounts/:id` | Get account details | |
| DELETE | `/v1/accounts/:id` | Delete account | +10 |
| POST | `/v1/accounts/:id/messages` | Send email | -1 |
| GET | `/v1/accounts/:id/messages` | List messages | |
| GET | `/v1/accounts/:id/messages/:msgId` | Get full message | |
| GET | `/v1/accounts/:id/messages/:msgId/attachments/:attId` | Get attachment URL | |
| POST | `/v1/accounts/:id/webhooks` | Register webhook | |
| GET | `/v1/accounts/:id/webhooks` | List webhooks | |
| DELETE | `/v1/accounts/:id/webhooks/:whId` | Delete webhook | |
| GET | `/v1/karma` | Get balance + events | |

## Karma system

Every action has a karma cost or reward:

| Event | Karma | Why |
|---|---|---|
| `money_paid` | +100 | Purchase credits |
| `email_received` | +2 | Someone replied from a trusted domain |
| `account_deleted` | +10 | Karma refunded when you delete an address |
| `email_sent` | -1 | Sending costs karma |
| `account_created` | -10 | Creating addresses costs karma |

**Important rules:**
- Karma is only awarded for inbound emails from trusted providers (Gmail, Outlook, Yahoo, iCloud, ProtonMail, Fastmail, Hey, etc.). Emails from unknown/throwaway domains don't earn karma.
- You only earn karma once per sender until the agent replies. If sender X emails you 5 times without a reply, only the first earns karma. Reply to X, and the next email from X earns karma again.
- Deleting an account refunds the 10 karma it cost to create.

When karma reaches 0, sends and account creation r
