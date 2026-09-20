---
name: azure-networking
description: Configure Azure VNets, NSGs, and Azure Firewall. Implement hub-spoke topology and private endpoints. Use when designing Azure network infrastructure. 
category: AI & Agents
source: antigravity
tags: [ai, agent, template, design, security, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-networking
---


# Azure Networking

Design and implement Azure network infrastructure including VNets, subnets, NSGs, VNet peering, private endpoints, Azure Firewall, and Application Gateway. Covers both az CLI commands and Terraform configurations for production hub-spoke topologies.

## Prerequisites

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login and set subscription
az login
az account set --subscription "my-subscription-id"

# Register required providers
az provider register --namespace Microsoft.Network

# Create resource group
az group create --name networking-rg --location eastus
```

## VNet and Subnet Creation

### Hub VNet

```bash
# Create hub VNet for shared services
az network vnet create \
  --resource-group networking-rg \
  --name hub-vnet \
  --address-prefix 10.0.0.0/16 \
  --location eastus \
  --tags environment=prod role=hub

# Add subnets to hub
az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name hub-vnet \
  --name AzureFirewallSubnet \
  --address-prefix 10.0.1.0/26

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name hub-vnet \
  --name GatewaySubnet \
  --address-prefix 10.0.2.0/27

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name hub-vnet \
  --name SharedServicesSubnet \
  --address-prefix 10.0.3.0/24

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name hub-vnet \
  --name AzureBastionSubnet \
  --address-prefix 10.0.4.0/26
```

### Spoke VNet

```bash
# Create spoke VNet for application workloads
az network vnet create \
  --resource-group networking-rg \
  --name spoke-prod-vnet \
  --address-prefix 10.1.0.0/16 \
  --location eastus \
  --tags environment=prod role=spoke

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name web-subnet \
  --address-prefix 10.1.1.0/24

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name app-subnet \
  --address-prefix 10.1.2.0/24

az network vnet subnet create \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name data-subnet \
  --address-prefix 10.1.3.0/24 \
  --private-endpoint-network-policies Enabled

# List all subnets in a VNet
az network vnet subnet list \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --output table
```

## Network Security Groups

```bash
# Create NSG for web tier
az network nsg create \
  --resource-group networking-rg \
  --name web-nsg \
  --tags tier=web

# Allow HTTPS from internet
az network nsg rule create \
  --resource-group networking-rg \
  --nsg-name web-nsg \
  --name AllowHTTPS \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes Internet \
  --destination-port-ranges 443

# Allow HTTP for redirect
az network nsg rule create \
  --resource-group networking-rg \
  --nsg-name web-nsg \
  --name AllowHTTP \
  --priority 110 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes Internet \
  --destination-port-ranges 80

# Deny all other inbound traffic
az network nsg rule create \
  --resource-group networking-rg \
  --nsg-name web-nsg \
  --name DenyAllInbound \
  --priority 4096 \
  --direction Inbound \
  --access Deny \
  --protocol '*' \
  --source-address-prefixes '*' \
  --destination-port-ranges '*'

# Create NSG for app tier -- only allow from web subnet
az network nsg create \
  --resource-group networking-rg \
  --name app-nsg

az network nsg rule create \
  --resource-group networking-rg \
  --nsg-name app-nsg \
  --name AllowFromWeb \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes 10.1.1.0/24 \
  --destination-port-ranges 8080

# Create NSG for data tier -- only allow from app subnet
az network nsg create \
  --resource-group networking-rg \
  --name data-nsg

az network nsg rule create \
  --resource-group networking-rg \
  --nsg-name data-nsg \
  --name AllowSQLFromApp \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes 10.1.2.0/24 \
  --destination-port-ranges 1433

# Associate NSG with subnet
az network vnet subnet update \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name web-subnet \
  --network-security-group web-nsg

az network vnet subnet update \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name app-subnet \
  --network-security-group app-nsg

az network vnet subnet update \
  --resource-group networking-rg \
  --vnet-name spoke-prod-vnet \
  --name data-subnet \
  --network-security-group data-nsg

# View effective NSG rules
az network nic list-effective-nsg \
  --resource-group networking-rg \
  --name myvm-nic \
  --output table
```

## VNet Peering

```bash
# Peer hub to spoke
az network vnet peering create \
  --resou
