---
name: audit-logging
description: Implement centralized audit logging and SIEM integration. Configure log retention and security monitoring. Use when implementing audit trail requirements. 
category: AI & Agents
source: antigravity
tags: [python, node, markdown, api, ai, agent, llm, template, security, kubernetes]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/audit-logging
---


# Audit Logging

Implement comprehensive audit logging for compliance, security monitoring, and forensic analysis across infrastructure and applications.

## When to Use

- Setting up centralized logging for compliance frameworks (SOC 2, HIPAA, PCI DSS)
- Implementing security event monitoring and alerting
- Building audit trails for regulatory requirements
- Configuring log retention and tamper-proof storage
- Integrating application logs with SIEM platforms

## Log Categories

```yaml
audit_events:
  authentication:
    - Login attempts (success and failure)
    - MFA enrollment and verification events
    - Session creation, renewal, and termination
    - Password changes and resets
    - API key and token generation

  authorization:
    - Access grants and denials
    - Permission changes and role assignments
    - Privilege escalation events
    - Resource sharing modifications
    - Policy evaluation results

  data_access:
    - Read operations on sensitive data
    - Write and update operations
    - Delete and purge operations
    - Bulk export and download events
    - Data classification changes

  administrative:
    - Configuration changes
    - User and group management
    - System startup and shutdown
    - Backup and restore operations
    - Network and firewall rule changes

  system:
    - Service health state changes
    - Resource provisioning and deprovisioning
    - Certificate and key rotation events
    - Scheduled job execution results
    - Integration and webhook events
```

## Rsyslog Configuration for Centralized Logging

```bash
# /etc/rsyslog.d/50-audit.conf

# Load imfile module to read application logs
module(load="imfile")

# Forward auth logs
input(type="imfile"
  File="/var/log/auth.log"
  Tag="auth"
  Severity="info"
  Facility="auth"
)

# Forward application audit logs
input(type="imfile"
  File="/var/log/app/audit.log"
  Tag="app-audit"
  Severity="info"
  Facility="local0"
)

# Structured JSON template
template(name="json-audit" type="list") {
  constant(value="{")
  constant(value="\"@timestamp\":\"")    property(name="timereported" dateFormat="rfc3339")
  constant(value="\",\"host\":\"")       property(name="hostname")
  constant(value="\",\"severity\":\"")   property(name="syslogseverity-text")
  constant(value="\",\"facility\":\"")   property(name="syslogfacility-text")
  constant(value="\",\"tag\":\"")        property(name="syslogtag" format="json")
  constant(value="\",\"message\":\"")    property(name="msg" format="json")
  constant(value="\"}\n")
}

# Forward to central syslog server over TLS
action(
  type="omfwd"
  target="syslog.internal.example.com"
  port="6514"
  protocol="tcp"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="x509/name"
  template="json-audit"
  queue.type="LinkedList"
  queue.size="50000"
  queue.filename="fwd_audit"
  queue.saveonshutdown="on"
  action.resumeRetryCount="-1"
)
```

## Journald Configuration for Persistent Logging

```ini
# /etc/systemd/journald.conf
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
MaxRetentionSec=365d
MaxFileSec=30d
SystemMaxUse=10G
SystemKeepFree=2G
ForwardToSyslog=yes
```

```bash
# Query journald for audit events
journalctl _TRANSPORT=audit --since "24 hours ago" --output json-pretty

# Filter by specific audit types
journalctl _AUDIT_TYPE=1112 --since today  # user login events
journalctl _AUDIT_TYPE=1100 --since today  # user auth events

# Export for offline analysis
journalctl --since "7 days ago" --output export > /backup/journal-export.bin
```

## Application Logging with Structured JSON

```python
import logging
import json
import hashlib
from datetime import datetime, timezone
from functools import wraps

class AuditLogger:
    def __init__(self, service_name, logger_name="audit"):
        self.service = service_name
        self.logger = logging.getLogger(logger_name)
        handler = logging.FileHandler("/var/log/app/audit.log")
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self._prev_hash = None

    def log_event(self, event_type, user, resource, action, result,
                  metadata=None, source_ip=None):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service,
            "event_type": event_type,
            "user": user,
            "resource": resource,
            "action": action,
            "result": result,
            "source_ip": source_ip,
            "metadata": metadata or {},
        }
        # Chain hash for tamper detection
        raw = json.dumps(log_entry, sort_keys=True)
        log_entry["prev_hash"] = self._prev_hash
        log_entry["hash"] = hashlib.sha256(
            f"{self._prev_hash}:{raw}".encode()
        ).hexdigest()
        self._prev_hash = log_entry["hash"]
        self.logger.info(json.dumps(log_entry))

    def log_auth(self, user,
