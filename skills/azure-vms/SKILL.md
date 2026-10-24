---
name: azure-vms
description: Manage Azure Virtual Machines and scale sets. Configure availability sets and managed disks. Use when deploying compute resources on Azure. 
category: AI & Agents
source: antigravity
tags: [ai, agent, template, design, image, security, docker, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-vms
---


# Azure Virtual Machines

Deploy and manage Azure VMs, availability sets, scale sets, custom images, and managed disks. Covers VM creation, sizing, disk management, auto-scaling, and Terraform configurations for production environments.

## Prerequisites

Examples are independent fragments. Confirm subscription, cost/quota, region/image availability, approved NSG/subnet and private access before provisioning. Cloud-init must be a real file with #cloud-config, not the commented shell excerpt. The backup vault/policy, load balancer and probe are prerequisites, not created here; default public endpoints in other examples must be explicitly replaced with the approved private network design. Docker group membership grants host-level control.

```bash
# Install Azure CLI
# Prerequisite: organization-approved Azure CLI installed from a verified signed package.
az version

# Login and set subscription
az login
az account set --subscription "my-subscription-id"

# Create resource group
az group create --name compute-rg --location eastus

# List available VM sizes in a region
az vm list-sizes --location eastus --output table

# List available VM images
az vm image list --output table
az vm image list --publisher Canonical --offer 0001-com-ubuntu-server-jammy --all --output table
```

## VM Creation

### Linux VM with SSH Key

```bash
az vm create \
  --resource-group compute-rg \
  --name myapp-vm \
  --image Ubuntu2204 \
  --size Standard_D4s_v5 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --vnet-name myapp-vnet \
  --subnet app-subnet \
  --nsg myapp-nsg \
  --public-ip-address "" \
  --os-disk-size-gb 64 \
  --os-disk-caching ReadWrite \
  --storage-sku Premium_LRS \
  --zone 1 \
  --assign-identity \
  --tags environment=prod team=platform app=myapp

# SSH into the VM (if public IP assigned)
# This example has no public IP; connect through approved Bastion/VPN/private SSH.
```

### Windows VM

Run interactively: omit --admin-password and enter a unique generated password at the CLI’s hidden prompt, or use approved secret-backed infrastructure provisioning. Never put it in argv/history.

```bash
az vm create \
  --resource-group compute-rg \
  --name myapp-win-vm \
  --image Win2022Datacenter \
  --size Standard_D4s_v5 \
  --admin-username azureadmin \
  --vnet-name myapp-vnet \
  --subnet app-subnet \
  --public-ip-address "" \
  --os-disk-size-gb 128 \
  --storage-sku Premium_LRS \
  --zone 1
```

### VM with Cloud-Init

```bash
# cloud-init.yaml
# #cloud-config
# package_update: true
# packages:
#   - nginx
#   - docker.io
# runcmd:
#   - systemctl enable nginx
#   - systemctl start nginx
#   - usermod -aG docker azureuser

az vm create \
  --resource-group compute-rg \
  --name web-vm \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --custom-data cloud-init.yaml \
  --tags role=web
```

## VM Size Guide

| Family | Example Sizes | Use Case |
|--------|---------------|----------|
| B-series | Standard_B1s, Standard_B2s | Dev/test, low-traffic web servers |
| D-series | Standard_D4s_v5, Standard_D8s_v5 | General purpose, most production workloads |
| E-series | Standard_E4s_v5, Standard_E16s_v5 | Memory-intensive (databases, caching) |
| F-series | Standard_F4s_v2, Standard_F16s_v2 | CPU-intensive (batch processing, analytics) |
| L-series | Standard_L8s_v3, Standard_L32s_v3 | Storage-optimized (big data, SQL) |
| N-series | Standard_NC6s_v3, Standard_NC24ads_A100_v4 | GPU workloads (ML training, rendering) |
| M-series | Standard_M128s | SAP HANA, large in-memory workloads |

```bash
# Find VM sizes with specific capabilities
az vm list-sizes --location eastus \
  --query "[?numberOfCores >= \`4\` && memoryInMb >= \`16000\`]" \
  --output table

# Check VM size availability in a zone
az vm list-skus --location eastus \
  --size Standard_D4s_v5 \
  --output table
```

## Managed Disks

```bash
# Add a data disk to existing VM
az vm disk attach \
  --resource-group compute-rg \
  --vm-name myapp-vm \
  --name myapp-data-disk \
  --size-gb 256 \
  --sku Premium_LRS \
  --new \
  --lun 0

# Create a standalone managed disk
az disk create \
  --resource-group compute-rg \
  --name shared-data-disk \
  --size-gb 512 \
  --sku Premium_LRS \
  --zone 1

# Example offline resize; supported online expansion depends on disk/VM configuration.
# Back up and schedule downtime; after Azure expansion grow the guest partition/filesystem safely.
az vm deallocate --resource-group compute-rg --name myapp-vm
az disk update \
  --resource-group compute-rg \
  --name myapp-data-disk \
  --size-gb 512
az vm start --resource-group compute-rg --name myapp-vm

# Snapshot a disk for backup
az snapshot create \
  --resource-group compute-rg \
  --name myapp-disk-snapshot \
  --source myapp-data-disk

# Create disk from snapshot
az disk create \
  --resource-group compute-rg \
  --name myapp-disk-from-snap \
  --source myapp-disk-snapshot \
  --sku Premium_LRS

# List d
