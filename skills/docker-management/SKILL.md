---
name: docker-management
description: Build, optimize, and troubleshoot Docker containers and images. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, agent, template, image, security, docker]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/docker-management
---


# Docker Management

Build, run, and manage Docker containers for application deployment and development.

## When to Use This Skill

Use this skill when:
- Creating and optimizing Dockerfiles
- Building and tagging Docker images
- Running and managing containers
- Debugging container issues
- Configuring Docker networking and volumes
- Implementing container security best practices

## Prerequisites

- Docker Engine installed (20.10+)
- Basic command line knowledge
- Understanding of application deployment

## Dockerfile Best Practices

### Multi-Stage Build

```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS production
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
USER nodejs
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### Layer Optimization

```dockerfile
FROM python:3.12-slim

# Install dependencies first (cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (changes frequently)
COPY . .

CMD ["python", "app.py"]
```

### Security Hardening

```dockerfile
FROM node:20-alpine

# Create non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -D appuser

WORKDIR /app

# Copy with proper ownership
COPY --chown=appuser:appgroup . .

# Drop privileges
USER appuser

# Use exec form for proper signal handling
CMD ["node", "server.js"]
```

## Building Images

### Basic Build

```bash
# Build with tag
docker build -t myapp:1.0 .

# Build with build args
docker build --build-arg NODE_ENV=production -t myapp:prod .

# Build for specific platform
docker build --platform linux/amd64 -t myapp:amd64 .

# Build with no cache
docker build --no-cache -t myapp:fresh .
```

### Multi-Platform Builds

```bash
# Create builder
docker buildx create --name multiplatform --use

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t myregistry/myapp:latest \
  --push .
```

## Running Containers

### Basic Operations

```bash
# Run container
docker run -d --name myapp -p 8080:3000 myapp:latest

# Run with environment variables
docker run -d \
  -e DATABASE_URL=postgres://localhost/db \
  -e NODE_ENV=production \
  myapp:latest

# Run with resource limits
docker run -d \
  --memory="512m" \
  --cpus="1.0" \
  myapp:latest

# Run with restart policy
docker run -d --restart=unless-stopped myapp:latest
```

### Volume Management

```bash
# Named volume
docker volume create mydata
docker run -v mydata:/app/data myapp:latest

# Bind mount
docker run -v $(pwd)/config:/app/config:ro myapp:latest

# tmpfs mount (memory)
docker run --tmpfs /tmp:rw,noexec,nosuid myapp:latest
```

### Networking

```bash
# Create network
docker network create mynetwork

# Run on network
docker run -d --network mynetwork --name api myapp:latest

# Connect existing container
docker network connect mynetwork existing-container

# Expose specific ports
docker run -d -p 127.0.0.1:8080:3000 myapp:latest
```

## Container Lifecycle

### Management Commands

```bash
# List containers
docker ps -a

# Stop container
docker stop myapp

# Remove container
docker rm myapp

# Force remove running container
docker rm -f myapp

# Prune stopped containers
docker container prune -f
```

### Logs and Monitoring

```bash
# View logs
docker logs myapp

# Follow logs
docker logs -f --tail 100 myapp

# View resource usage
docker stats myapp

# Inspect container
docker inspect myapp
```

## Debugging Containers

### Interactive Access

```bash
# Execute command in running container
docker exec -it myapp /bin/sh

# Run container with shell
docker run -it --rm myapp:latest /bin/sh

# Debug failed container
docker run -it --entrypoint /bin/sh myapp:latest
```

### Troubleshooting

```bash
# Check container logs for errors
docker logs myapp 2>&1 | grep -i error

# Inspect container state
docker inspect --format='{{.State.Status}}' myapp

# Check container processes
docker top myapp

# View container filesystem changes
docker diff myapp

# Export container filesystem
docker export myapp > myapp-fs.tar
```

### Health Checks

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' myapp
```

## Image Management

### Tagging and Pushing

```bash
# Tag image
docker tag myapp:latest myregistry.com/myapp:v1.0

# Push to registry
docker push myregistry.com/myapp:v1.0

# Pull image
docker pull myregistry.com/myapp:v1.0
```

### Cleanup

```bash
# Remove unused images
docker image prune -a

# Remove all unused resources
docker system prune -a --volumes

# Remove specifi
