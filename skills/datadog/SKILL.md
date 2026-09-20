---
name: datadog
description: Implement Datadog monitoring and APM for infrastructure and applications. 
category: AI & Agents
source: antigravity
tags: [python, javascript, node, api, ai, agent, template, image, security, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/datadog
---


# Datadog

Monitor infrastructure and applications with Datadog's unified observability platform.

## When to Use This Skill

Use this skill when:
- Implementing enterprise-grade monitoring
- Setting up APM and distributed tracing
- Creating unified dashboards for infrastructure and apps
- Configuring intelligent alerting
- Monitoring cloud infrastructure (AWS, Azure, GCP)

## Prerequisites

- Datadog account and API key
- Agent installation access
- Application code access for APM

## Agent Installation

### Linux

```bash
# Install agent
DD_API_KEY=<YOUR_API_KEY> DD_SITE="datadoghq.com" bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script_agent7.sh)"

# Or via package manager
apt-get update && apt-get install datadog-agent

# Configure API key
echo "api_key: YOUR_API_KEY" >> /etc/datadog-agent/datadog.yaml

# Start agent
systemctl start datadog-agent
systemctl enable datadog-agent
```

### Docker

```yaml
# docker-compose.yml
version: '3.8'

services:
  datadog-agent:
    image: gcr.io/datadoghq/agent:7
    environment:
      - DD_API_KEY=${DD_API_KEY}
      - DD_SITE=datadoghq.com
      - DD_LOGS_ENABLED=true
      - DD_APM_ENABLED=true
      - DD_PROCESS_AGENT_ENABLED=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc/:/host/proc/:ro
      - /sys/fs/cgroup/:/host/sys/fs/cgroup:ro
    ports:
      - "8126:8126"  # APM
      - "8125:8125/udp"  # DogStatsD
```

### Kubernetes

```bash
# Using Helm
helm repo add datadog https://helm.datadoghq.com

helm install datadog datadog/datadog \
  --set datadog.apiKey=${DD_API_KEY} \
  --set datadog.site=datadoghq.com \
  --set datadog.logs.enabled=true \
  --set datadog.apm.portEnabled=true \
  --set datadog.processAgent.enabled=true \
  --namespace datadog \
  --create-namespace
```

## Agent Configuration

```yaml
# /etc/datadog-agent/datadog.yaml
api_key: YOUR_API_KEY
site: datadoghq.com

# Hostname
hostname: myserver.example.com

# Tags applied to all metrics
tags:
  - env:production
  - service:myapp
  - team:platform

# Log collection
logs_enabled: true

# APM
apm_config:
  enabled: true
  apm_dd_url: https://trace.agent.datadoghq.com

# Process monitoring
process_config:
  enabled: true

# Container monitoring
container_collect_all: true
docker_labels_as_tags:
  app: service
  environment: env
```

## Integration Configuration

### MySQL

```yaml
# /etc/datadog-agent/conf.d/mysql.d/conf.yaml
init_config:

instances:
  - host: localhost
    port: 3306
    username: datadog
    password: <PASSWORD>
    tags:
      - env:production
    options:
      replication: true
      extra_status_metrics: true
```

### PostgreSQL

```yaml
# /etc/datadog-agent/conf.d/postgres.d/conf.yaml
init_config:

instances:
  - host: localhost
    port: 5432
    username: datadog
    password: <PASSWORD>
    dbname: mydb
    collect_activity_metrics: true
    collect_database_size_metrics: true
```

### NGINX

```yaml
# /etc/datadog-agent/conf.d/nginx.d/conf.yaml
init_config:

instances:
  - nginx_status_url: http://localhost:80/nginx_status
    tags:
      - env:production
```

## Log Collection

### File-Based Logs

```yaml
# /etc/datadog-agent/conf.d/myapp.d/conf.yaml
logs:
  - type: file
    path: /var/log/myapp/*.log
    service: myapp
    source: python
    sourcecategory: custom
    tags:
      - env:production

  - type: file
    path: /var/log/nginx/access.log
    service: nginx
    source: nginx
    log_processing_rules:
      - type: exclude_at_match
        name: exclude_healthchecks
        pattern: health_check
```

### Docker Logs

```yaml
# docker-compose.yml
services:
  myapp:
    labels:
      com.datadoghq.ad.logs: '[{"source": "python", "service": "myapp"}]'
```

### Kubernetes Logs

```yaml
# Pod annotation
apiVersion: v1
kind: Pod
metadata:
  annotations:
    ad.datadoghq.com/myapp.logs: |
      [{
        "source": "python",
        "service": "myapp",
        "log_processing_rules": [{
          "type": "multi_line",
          "name": "python_tracebacks",
          "pattern": "^Traceback"
        }]
      }]
```

## APM Configuration

### Python

```python
from ddtrace import patch_all, tracer

# Automatic instrumentation
patch_all()

# Configure tracer
tracer.configure(
    hostname='localhost',
    port=8126,
    service='myapp',
    env='production',
    version='1.0.0'
)

# Manual instrumentation
@tracer.wrap(service='myapp', resource='process_order')
def process_order(order_id):
    with tracer.trace('validate_order') as span:
        span.set_tag('order_id', order_id)
        # Validation logic
    
    with tracer.trace('save_order'):
        # Save logic
        pass
```

```bash
# Install library
pip install ddtrace

# Run with auto-instrumentation
ddtrace-run python app.py
```

### Node.js

```javascript
const tracer = require('dd-trace').init({
  service: 'myapp',
  env: 'production',
  version: '1.0.0',
  logInjection: true
});

// Manual instrumentation
const span = tracer.startSpan('custom_
