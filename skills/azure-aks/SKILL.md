---
name: azure-aks
description: Deploy and manage Azure Kubernetes Service clusters. Configure node pools, networking, and integrations. Use when running Kubernetes workloads on Azure. 
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, template, image, security, docker, kubernetes, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-aks
---


# Azure Kubernetes Service

Deploy and manage production-grade Kubernetes clusters on Azure with AKS. Covers cluster creation, node pool management, networking, ingress controllers, monitoring, security, and Terraform-based provisioning.

## When to Use

- You need managed Kubernetes without maintaining control plane infrastructure.
- Your workloads require container orchestration with auto-scaling.
- You need tight integration with Azure AD, Key Vault, and Container Registry.
- You are running microservices that require service mesh, ingress, or network policies.
- You need GPU or spot node pools for specialized or cost-optimized workloads.

## Prerequisites

```bash
# Install Azure CLI and kubectl
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az aks install-cli

# Login and set subscription
az login
az account set --subscription "my-subscription-id"

# Register required providers
az provider register --namespace Microsoft.ContainerService
az provider register --namespace Microsoft.OperationsManagement

# Verify kubectl
kubectl version --client
```

## Cluster Creation

### Basic Production Cluster

```bash
# Create resource group
az group create --name myapp-rg --location eastus

# Create AKS cluster with best-practice defaults
az aks create \
  --resource-group myapp-rg \
  --name myapp-aks \
  --node-count 3 \
  --node-vm-size Standard_D4s_v5 \
  --enable-managed-identity \
  --enable-cluster-autoscaler \
  --min-count 2 \
  --max-count 10 \
  --network-plugin azure \
  --network-policy calico \
  --service-cidr 10.1.0.0/16 \
  --dns-service-ip 10.1.0.10 \
  --vnet-subnet-id "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}" \
  --enable-aad \
  --aad-admin-group-object-ids "{aad-group-id}" \
  --enable-azure-rbac \
  --zones 1 2 3 \
  --generate-ssh-keys \
  --tags environment=prod team=platform

# Get cluster credentials
az aks get-credentials --resource-group myapp-rg --name myapp-aks

# Verify cluster access
kubectl get nodes -o wide
kubectl cluster-info
```

### Private Cluster

```bash
az aks create \
  --resource-group myapp-rg \
  --name myapp-private-aks \
  --node-count 3 \
  --node-vm-size Standard_D4s_v5 \
  --enable-managed-identity \
  --enable-private-cluster \
  --private-dns-zone system \
  --network-plugin azure \
  --vnet-subnet-id "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}" \
  --generate-ssh-keys
```

## Node Pool Management

```bash
# Add a user node pool for application workloads
az aks nodepool add \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --name apppool \
  --node-count 3 \
  --node-vm-size Standard_D8s_v5 \
  --mode User \
  --enable-cluster-autoscaler \
  --min-count 2 \
  --max-count 15 \
  --zones 1 2 3 \
  --labels workload=app tier=frontend \
  --node-taints dedicated=app:NoSchedule \
  --max-pods 50

# Add GPU node pool for ML workloads
az aks nodepool add \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --name gpupool \
  --node-count 1 \
  --node-vm-size Standard_NC6s_v3 \
  --mode User \
  --enable-cluster-autoscaler \
  --min-count 0 \
  --max-count 4 \
  --node-taints sku=gpu:NoSchedule \
  --labels workload=ml

# Add spot instance pool for batch workloads
az aks nodepool add \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --name spotpool \
  --node-count 2 \
  --node-vm-size Standard_D4s_v5 \
  --priority Spot \
  --eviction-policy Delete \
  --spot-max-price -1 \
  --enable-cluster-autoscaler \
  --min-count 0 \
  --max-count 20 \
  --labels workload=batch

# Scale a node pool manually
az aks nodepool scale \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --name apppool \
  --node-count 5

# Upgrade a node pool
az aks nodepool upgrade \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --name apppool \
  --kubernetes-version 1.28.3

# List node pools
az aks nodepool list \
  --resource-group myapp-rg \
  --cluster-name myapp-aks \
  --output table
```

## Ingress Controller Setup

```bash
# Install NGINX ingress controller via Helm
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --set controller.replicaCount=2 \
  --set controller.nodeSelector."kubernetes\.io/os"=linux \
  --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz \
  --set controller.service.externalTrafficPolicy=Local

# Verify the ingress controller and get external IP
kubectl get svc -n ingress-nginx
```

### Ingress Resource Example

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myapp-ingress
  namespace: myapp
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m
