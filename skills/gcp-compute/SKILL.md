---
name: gcp-compute
description: Manage Compute Engine instances and instance templates. Configure managed instance groups and preemptible VMs. Use when deploying compute resources on GCP. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, template, image, security, gcp, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-compute
---


# GCP Compute Engine

Deploy, manage, and scale Compute Engine virtual machines on Google Cloud Platform.

## When to Use

- Deploying web servers, application backends, or batch-processing workloads on GCP
- Running workloads that need full OS-level control (unlike Cloud Run or App Engine)
- Creating managed instance groups for auto-healing and auto-scaling behind a load balancer
- Provisioning GPU-attached VMs for ML training or rendering pipelines
- Cost-optimizing non-critical workloads with preemptible or spot VMs

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and authenticated
- A GCP project with the Compute Engine API enabled
- IAM role `roles/compute.admin` or scoped roles for instance management

```bash
gcloud auth list
gcloud config set project $PROJECT_ID
gcloud services enable compute.googleapis.com
```

## Machine Types Reference

| Family | Example | vCPUs | Memory | Use Case |
|--------|---------|-------|--------|----------|
| E2 | e2-micro | 0.25 | 1 GB | Dev/test, microservices |
| E2 | e2-medium | 1 | 4 GB | Light web servers |
| N2 | n2-standard-4 | 4 | 16 GB | General-purpose production |
| N2 | n2-highmem-8 | 8 | 64 GB | In-memory caches, databases |
| C2 | c2-standard-16 | 16 | 64 GB | Compute-intensive, HPC |

```bash
# List machine types available in a zone
gcloud compute machine-types list --zones=us-central1-a --filter="name~'e2-'"

# Create a custom machine type (6 vCPUs, 24 GB RAM)
gcloud compute instances create custom-vm \
  --custom-cpu=6 --custom-memory=24GB \
  --zone=us-central1-a \
  --image-family=debian-12 --image-project=debian-cloud
```

## Create an Instance

```bash
# Production instance with shielded VM and startup script
gcloud compute instances create web-server \
  --machine-type=e2-medium \
  --zone=us-central1-a \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-balanced \
  --tags=http-server,https-server \
  --labels=env=production,team=backend \
  --metadata=enable-oslogin=TRUE \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring

# Instance with a startup script and service account
gcloud compute instances create app-server \
  --machine-type=e2-standard-2 \
  --zone=us-central1-a \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --metadata-from-file=startup-script=startup.sh \
  --service-account=app-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --scopes=cloud-platform

# Instance with an additional data disk
gcloud compute instances create db-server \
  --machine-type=n2-highmem-4 \
  --zone=us-central1-a \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=20GB \
  --create-disk=name=data-disk,size=200GB,type=pd-ssd,auto-delete=no
```

## Startup Script Example

```bash
#!/bin/bash
# startup.sh - runs on first boot and every reboot
set -euo pipefail
apt-get update && apt-get install -y nginx
systemctl enable nginx && systemctl start nginx
curl -X PUT -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/startup/status" \
  -d "complete"
```

## Instance Templates and Managed Instance Groups

```bash
# Create an instance template
gcloud compute instance-templates create web-template \
  --machine-type=e2-medium \
  --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=20GB --tags=http-server \
  --metadata-from-file=startup-script=startup.sh

# Create a regional managed instance group (MIG) with health check
gcloud compute health-checks create http http-health-check \
  --port=80 --request-path=/healthz \
  --check-interval=10s --timeout=5s \
  --healthy-threshold=2 --unhealthy-threshold=3

gcloud compute instance-groups managed create web-mig \
  --template=web-template --size=3 \
  --region=us-central1 \
  --health-check=http-health-check --initial-delay=120

# Configure autoscaling
gcloud compute instance-groups managed set-autoscaling web-mig \
  --region=us-central1 \
  --min-num-replicas=2 --max-num-replicas=10 \
  --target-cpu-utilization=0.65 --cool-down-period=90

# Rolling update to a new template
gcloud compute instance-groups managed rolling-action start-update web-mig \
  --version=template=web-template-v2 \
  --region=us-central1 --max-surge=3 --max-unavailable=0
```

## Preemptible and Spot VMs

```bash
# Spot VM (recommended over legacy preemptible)
gcloud compute instances create spot-worker \
  --machine-type=n2-standard-8 \
  --zone=us-central1-a \
  --image-family=debian-12 --image-project=debian-cloud \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP

# Spot instance template for batch MIG
gcloud compute instance-templates create batch-template \
  --machine-type=n2-standard-4 \
  --image-family=debian-12 --image-project=debian-cloud \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE
```

## Snapshots and Images

```bash
# Create a snapshot
