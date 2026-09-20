---
name: azure-devops
description: Set up Azure Pipelines for CI/CD, configure build and release pipelines, manage Azure DevOps projects, and integrate with Azure services. 
category: Development & Code Tools
source: antigravity
tags: [node, api, ai, agent, template, image, security, docker, kubernetes, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-devops
---


# Azure DevOps Pipelines

Build, test, and deploy applications using Azure Pipelines with YAML or classic editor.

## When to Use This Skill

Use this skill when:
- Creating CI/CD pipelines in Azure DevOps
- Configuring build and release stages
- Managing Azure DevOps service connections
- Deploying to Azure or other cloud platforms
- Setting up multi-stage YAML pipelines

## Prerequisites

- Azure DevOps organization and project
- Service connections for target environments
- Basic YAML understanding
- Azure subscription (for Azure deployments)

## YAML Pipeline Structure

Create `azure-pipelines.yml` in repository root:

```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - src/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'
  nodeVersion: '20.x'

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: $(nodeVersion)
          - script: |
              npm ci
              npm run build
            displayName: 'Build application'
          - publish: $(Build.ArtifactStagingDirectory)
            artifact: drop

  - stage: Deploy
    dependsOn: Build
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployWeb
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: echo Deploying to production
```

## Triggers

### Branch Triggers

```yaml
trigger:
  branches:
    include:
      - main
      - release/*
    exclude:
      - feature/*
  tags:
    include:
      - v*
```

### Pull Request Triggers

```yaml
pr:
  branches:
    include:
      - main
  paths:
    include:
      - src/*
    exclude:
      - docs/*
```

### Scheduled Triggers

```yaml
schedules:
  - cron: '0 2 * * *'
    displayName: 'Nightly build'
    branches:
      include:
        - main
    always: true
```

## Jobs and Stages

### Parallel Jobs

```yaml
stages:
  - stage: Test
    jobs:
      - job: UnitTests
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: npm run test:unit
      
      - job: IntegrationTests
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: npm run test:integration
```

### Matrix Strategy

```yaml
jobs:
  - job: Build
    strategy:
      matrix:
        linux:
          vmImage: 'ubuntu-latest'
        windows:
          vmImage: 'windows-latest'
        mac:
          vmImage: 'macos-latest'
    pool:
      vmImage: $(vmImage)
    steps:
      - script: npm test
```

### Job Dependencies

```yaml
stages:
  - stage: Build
    jobs:
      - job: A
        steps:
          - script: echo Job A
      - job: B
        dependsOn: A
        steps:
          - script: echo Job B
```

## Variables and Parameters

### Variable Groups

```yaml
variables:
  - group: 'production-secrets'
  - name: buildConfiguration
    value: 'Release'
```

### Runtime Parameters

```yaml
parameters:
  - name: environment
    displayName: 'Environment'
    type: string
    default: 'dev'
    values:
      - dev
      - staging
      - prod

stages:
  - stage: Deploy
    variables:
      env: ${{ parameters.environment }}
    jobs:
      - job: Deploy
        steps:
          - script: echo "Deploying to $(env)"
```

### Secret Variables

```yaml
variables:
  - name: mySecret
    value: $(SECRET_FROM_PIPELINE)  # Set in pipeline settings

steps:
  - script: |
      echo "Using secret"
      ./deploy.sh
    env:
      API_KEY: $(mySecret)
```

## Templates

### Job Template

```yaml
# templates/build-job.yml
parameters:
  - name: nodeVersion
    default: '20'

jobs:
  - job: Build
    steps:
      - task: NodeTool@0
        inputs:
          versionSpec: ${{ parameters.nodeVersion }}
      - script: npm ci && npm run build
```

### Using Templates

```yaml
# azure-pipelines.yml
stages:
  - stage: Build
    jobs:
      - template: templates/build-job.yml
        parameters:
          nodeVersion: '20'
```

### Stage Template

```yaml
# templates/deploy-stage.yml
parameters:
  - name: environment
    type: string
  - name: serviceConnection
    type: string

stages:
  - stage: Deploy_${{ parameters.environment }}
    jobs:
      - deployment: Deploy
        environment: ${{ parameters.environment }}
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureWebApp@1
                  inputs:
                    azureSubscription: ${{ parameters.serviceConnection }}
                    appName: 'myapp-${{ parameters.environment }}'
```

## Deployments

### Environment Deployments

```yaml
stages:
  - stage: DeployStaging
    jobs:
      - deployment: DeployWeb
        environment: 'staging'
        strategy:
          runOnce:
            deploy:
              steps:
                - download: current
                  
