---
name: docker-compose
description: Define and run multi-container Docker applications using Docker Compose. 
category: Document Processing
source: antigravity
tags: [node, api, ai, agent, workflow, template, design, image, security, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/docker-compose
---


# Docker Compose

Orchestrate multi-container applications with declarative YAML configuration.

## When to Use This Skill

Use this skill when:
- Running multi-container applications locally
- Setting up development environments
- Defining service dependencies and networking
- Managing application stacks with multiple services
- Creating reproducible development setups

## Execution Scope

Confirm the selected Docker context and project before any operation. Build instructions execute contributed commands; inspect the Dockerfile, build context, scripts and downloaded dependencies first. Image publication, shared-container stops and volume deletion need authorization for the exact target. Do not expose environment values, image history or logs containing credentials. These examples are independent fragments with project-specific assets, not a complete deployment.

## Prerequisites

- Docker Engine with Compose plugin (v2)
- Basic Docker knowledge
- YAML syntax understanding

## Basic Configuration

### Simple Application Stack

```yaml
# docker-compose.yml

services:
  web:
    build: .
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgres://postgres:${POSTGRES_PASSWORD:?set a local fixture password}@db:5432/myapp
    depends_on:
      - db
      - redis

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set a local fixture password}
      POSTGRES_DB: myapp
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "127.0.0.1:5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"

volumes:
  postgres-data:
```

## Service Configuration

### Build Options

```yaml
services:
  app:
    build:
      context: ./app
      dockerfile: Dockerfile.dev
      args:
        NODE_VERSION: "20"
      target: development
      cache_from:
        - myapp:cache
    image: myapp:dev
```

### Environment Variables

```yaml
services:
  app:
    environment:
      - NODE_ENV=production
      - API_KEY=${API_KEY}  # From shell or .env file
    env_file:
      - .env
      - .env.local
```

### Port Mapping

```yaml
services:
  web:
    ports:
      - "127.0.0.1:3000:3000"           # HOST:CONTAINER
      - "127.0.0.1:9229:9229" # Bind to localhost only
      - "127.0.0.1:8080-8090:8080-8090" # Local development port range
    expose:
      - "3000"                # Internal only (no host binding)
```

### Volume Mounts

```yaml
services:
  app:
    volumes:
      # Named volume
      - app-data:/app/data
      # Bind mount
      - ./src:/app/src
      # Read-only bind mount
      - ./config:/app/config:ro
      # Anonymous volume (for node_modules)
      - /app/node_modules

volumes:
  app-data:
    driver: local
```

### Dependencies

```yaml
services:
  web:
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started

  db:
    image: postgres:15
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
```

## Networking

### Custom Networks

```yaml
services:
  frontend:
    networks:
      - frontend-net

  backend:
    networks:
      - frontend-net
      - backend-net

  db:
    networks:
      - backend-net

networks:
  frontend-net:
    driver: bridge
  backend-net:
    driver: bridge
    internal: true  # No external access
```

### Network Aliases

```yaml
services:
  db:
    networks:
      backend:
        aliases:
          - database
          - postgres

networks:
  backend:
```

## Resource Limits

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

The replicas fragment below cannot scale a service whose merged config binds every replica to one fixed host port. Use an explicitly configured reverse proxy/load balancer and remove conflicting published ports; verify the resolved config and effective resource limits for the installed Compose implementation. `depends_on` without a health condition controls start order, not application readiness or runtime recovery.

## Multiple Compose Files

### Override Files

```yaml
# docker-compose.yml (base)
services:
  web:
    image: myapp:latest
    ports:
      - "127.0.0.1:3000:3000"

# docker-compose.override.yml (development - auto-loaded)
services:
  web:
    build: .
    volumes:
      - ./src:/app/src
    environment:
      - DEBUG=true

# docker-compose.prod.yml (production)
services:
  web:
    deploy:
      replicas: 3
    environment:
      - DEBUG=false
```

### Using Multiple Files

```bash
# Development (uses override automatically)
docker compose up

# Production
docker compose -f docker-compose.yml -f docker-compose.prod.yml up

# Merge and view final config
docker compose -f docker-compose.yml -f docker-compose.prod.yml 
