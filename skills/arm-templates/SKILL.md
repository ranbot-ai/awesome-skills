---
name: arm-templates
description: Deploy Azure resources with ARM templates and Bicep. Create modular deployments and manage dependencies. Use when deploying Azure-native IaC. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, template, image, security, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/arm-templates
---


# ARM Templates & Bicep

Deploy Azure infrastructure with ARM templates and Bicep. Bicep is the recommended domain-specific language that compiles to ARM JSON, offering cleaner syntax, modules, and first-class tooling support.

Templates are separate illustrative fragments, not a complete resource graph. Module paths and parameter files named here are not bundled. Pin reviewed Bicep/provider API/image versions, verify resource IDs/subscription/region, and inspect What-If and replacement/deletion impact before authorized deployment. Validation/build success does not prove deployability, networking isolation, quotas or safe changes. Deleting a deployment record does not roll back deployed resources.

## Prerequisites

```bash
# Install Azure CLI
# Prerequisite: organization-approved Azure CLI installed from a verified signed package.
az version

# Install Bicep CLI (bundled with Azure CLI 2.20+)
az bicep install
az bicep upgrade

# Verify installation
az bicep version

# Login and set subscription
az login
az account set --subscription "my-subscription-id"
```

## Bicep Fundamentals

### Resource Group Deployment with Virtual Network

```bicep
// main.bicep
@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Environment name used for resource naming')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Base name for all resources')
param baseName string

var vnetName = '${baseName}-${environment}-vnet'
var nsgName = '${baseName}-${environment}-nsg'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPS'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'web-subnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
      {
        name: 'app-subnet'
        properties: {
          addressPrefix: '10.0.2.0/24'
        }
      }
      {
        name: 'data-subnet'
        properties: {
          addressPrefix: '10.0.3.0/24'
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output webSubnetId string = vnet.properties.subnets[0].id
output appSubnetId string = vnet.properties.subnets[1].id
```

### VM Deployment with Managed Identity

```bicep
// vm.bicep
param location string = resourceGroup().location
param vmName string
param subnetId string
param adminUsername string = 'azureuser'

@secure()
param adminPublicKey string

resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output vmPrincipalId string = vm.identity.principalId
output vmId string = vm.id
```

## Bicep Modules
