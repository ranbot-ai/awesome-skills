---
name: docker
description: Please check if docker is already installed. If so, to start Docker in a container environment: 
category: Development & Code Tools
source: openhands
tags: [docker, bash, agent]
url: https://github.com/OpenHands/OpenHands/blob/main/skills/docker.md
---


# Docker Usage Guide

## Starting Docker in Container Environments

Please check if docker is already installed. If so, to start Docker in a container environment:

```bash
# Start Docker daemon in the background
sudo dockerd > /tmp/docker.log 2>&1 &

# Wait for Docker to initialize
sleep 5
```

## Verifying Docker Installation

To verify Docker is working correctly, run the hello-world container:

```bash
sudo docker run hello-world
```
