---
name: devcontainers-nix
description: Create reproducible development environments with Dev Containers, Nix flakes, and Devbox for consistent toolchains across teams. 
category: Document Processing
source: antigravity
tags: [python, node, ai, agent, workflow, template, document, image, security, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/devcontainers-nix
---


# Dev Containers & Nix Environments

Reproducible, portable development environments that eliminate environment drift.

## When to Use This Skill

Use this skill when:
- Onboarding new developers (zero-to-productive in minutes)
- Standardizing toolchains across a team
- Eliminating "works on my machine" problems
- Setting up CI environments that match local dev
- Creating ephemeral, disposable dev environments

## Dev Containers

### Basic Configuration

```json
// .devcontainer/devcontainer.json
{
  "name": "My Project",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu-22.04",
  "features": {
    "ghcr.io/devcontainers/features/node:1": { "version": "20" },
    "ghcr.io/devcontainers/features/python:1": { "version": "3.12" },
    "ghcr.io/devcontainers/features/docker-in-docker:2": {},
    "ghcr.io/devcontainers/features/kubectl-helm-minikube:1": {}
  },
  "forwardPorts": [3000, 5432],
  "postCreateCommand": "npm install",
  "customizations": {
    "vscode": {
      "extensions": [
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "ms-python.python"
      ],
      "settings": {
        "editor.formatOnSave": true
      }
    }
  }
}
```

### Docker Compose Dev Container

```json
// .devcontainer/devcontainer.json
{
  "name": "Full Stack Dev",
  "dockerComposeFile": "docker-compose.yml",
  "service": "app",
  "workspaceFolder": "/workspace",
  "forwardPorts": [3000, 5432, 6379],
  "postCreateCommand": "npm install && npx prisma migrate dev"
}
```

```yaml
# .devcontainer/docker-compose.yml
services:
  app:
    build:
      context: ..
      dockerfile: .devcontainer/Dockerfile
    volumes:
      - ..:/workspace:cached
    command: sleep infinity
    depends_on: [db, redis]

  db:
    image: postgres:16
    environment:
      POSTGRES_DB: dev
      POSTGRES_USER: dev
      POSTGRES_PASSWORD: dev
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

### Custom Dockerfile

```dockerfile
# .devcontainer/Dockerfile
FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install project-specific tools
RUN curl -fsSL https://get.opentofu.org/install-opentofu.sh -o /tmp/install-opentofu.sh \
    && sh /tmp/install-opentofu.sh -s -- --install-method standalone \
    && rm /tmp/install-opentofu.sh
RUN curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install kubectl /usr/local/bin/

# Non-root user setup
USER vscode
WORKDIR /workspace
```

## Nix Flakes

### Basic Flake

```nix
# flake.nix
{
  description = "Project development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Languages
            nodejs_20
            python312
            go_1_22
            rustc
            cargo

            # Tools
            docker-compose
            kubectl
            kubernetes-helm
            opentofu
            awscli2
            jq
            yq-go

            # Databases
            postgresql_16
            redis
          ];

          shellHook = ''
            echo "Dev environment loaded"
            export PROJECT_ROOT=$(pwd)
            export PATH="$PROJECT_ROOT/node_modules/.bin:$PATH"
          '';
        };
      }
    );
}
```

```bash
# Enter the dev shell
nix develop

# Or run a single command
nix develop --command bash -c "node --version && go version"

# Build and run
nix build
nix run
```

### Pin Dependencies

```bash
# Lock flake inputs for reproducibility
nix flake lock
nix flake update  # Update all inputs

# Update a specific input
nix flake lock --update-input nixpkgs
```

## Devbox (Nix Made Simple)

Devbox wraps Nix with a friendlier interface:

```bash
# Install Devbox
curl -fsSL https://get.jetify.com/devbox -o /tmp/install-devbox.sh && sh /tmp/install-devbox.sh && rm /tmp/install-devbox.sh

# Initialize project
devbox init

# Add packages
devbox add nodejs@20 python@3.12 postgresql@16
devbox add go@1.22 kubectl helm

# Enter shell
devbox shell

# Run commands without entering shell
devbox run node --version
```

### devbox.json Configuration

```json
{
  "$schema": "https://raw.githubusercontent.com/jetify-com/devbox/main/.schema/devbox.schema.json",
  "packages": [
    "nodejs@20",
    "python@3.12",
    "go@1.22",
    "kubectl@1.29",
    "kubernetes-helm@3.14",
    "opentofu@1.8",
    "awscli2@2.15",
    "jq@1.7",
    "postgresql@16",
    "redis@7"
  ],
  
