---
name: azure-containerregistry-py
description: Azure Container Registry SDK for Python. Use for managing container images, artifacts, and repositories. Triggers: "azure-containerregistry", "ContainerRegistryClient", "container images", "docker reg
category: AI & Agents
source: antigravity
tags: [python, ai, image, docker, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-containerregistry-py
---


# Azure Container Registry SDK for Python

Manage container images, artifacts, and repositories in Azure Container Registry.

## Installation

```bash
pip install azure-containerregistry
```

## Environment Variables

```bash
AZURE_CONTAINERREGISTRY_ENDPOINT=https://<registry-name>.azurecr.io
```

## Authentication

### Entra ID (Recommended)

```python
from azure.containerregistry import ContainerRegistryClient
from azure.identity import DefaultAzureCredential

client = ContainerRegistryClient(
    endpoint=os.environ["AZURE_CONTAINERREGISTRY_ENDPOINT"],
    credential=DefaultAzureCredential()
)
```

### Anonymous Access (Public Registry)

```python
from azure.containerregistry import ContainerRegistryClient

client = ContainerRegistryClient(
    endpoint="https://mcr.microsoft.com",
    credential=None,
    audience="https://mcr.microsoft.com"
)
```

## List Repositories

```python
client = ContainerRegistryClient(endpoint, DefaultAzureCredential())

for repository in client.list_repository_names():
    print(repository)
```

## Repository Operations

### Get Repository Properties

```python
properties = client.get_repository_properties("my-image")
print(f"Created: {properties.created_on}")
print(f"Modified: {properties.last_updated_on}")
print(f"Manifests: {properties.manifest_count}")
print(f"Tags: {properties.tag_count}")
```

### Update Repository Properties

```python
from azure.containerregistry import RepositoryProperties

client.update_repository_properties(
    "my-image",
    properties=RepositoryProperties(
        can_delete=False,
        can_write=False
    )
)
```

### Delete Repository

```python
client.delete_repository("my-image")
```

## List Tags

```python
for tag in client.list_tag_properties("my-image"):
    print(f"{tag.name}: {tag.created_on}")
```

### Filter by Order

```python
from azure.containerregistry import ArtifactTagOrder

# Most recent first
for tag in client.list_tag_properties(
    "my-image",
    order_by=ArtifactTagOrder.LAST_UPDATED_ON_DESCENDING
):
    print(f"{tag.name}: {tag.last_updated_on}")
```

## Manifest Operations

### List Manifests

```python
from azure.containerregistry import ArtifactManifestOrder

for manifest in client.list_manifest_properties(
    "my-image",
    order_by=ArtifactManifestOrder.LAST_UPDATED_ON_DESCENDING
):
    print(f"Digest: {manifest.digest}")
    print(f"Tags: {manifest.tags}")
    print(f"Size: {manifest.size_in_bytes}")
```

### Get Manifest Properties

```python
manifest = client.get_manifest_properties("my-image", "latest")
print(f"Digest: {manifest.digest}")
print(f"Architecture: {manifest.architecture}")
print(f"OS: {manifest.operating_system}")
```

### Update Manifest Properties

```python
from azure.containerregistry import ArtifactManifestProperties

client.update_manifest_properties(
    "my-image",
    "latest",
    properties=ArtifactManifestProperties(
        can_delete=False,
        can_write=False
    )
)
```

### Delete Manifest

```python
# Delete by digest
client.delete_manifest("my-image", "sha256:abc123...")

# Delete by tag
manifest = client.get_manifest_properties("my-image", "old-tag")
client.delete_manifest("my-image", manifest.digest)
```

## Tag Operations

### Get Tag Properties

```python
tag = client.get_tag_properties("my-image", "latest")
print(f"Digest: {tag.digest}")
print(f"Created: {tag.created_on}")
```

### Delete Tag

```python
client.delete_tag("my-image", "old-tag")
```

## Upload and Download Artifacts

```python
from azure.containerregistry import ContainerRegistryClient

client = ContainerRegistryClient(endpoint, DefaultAzureCredential())

# Download manifest
manifest = client.download_manifest("my-image", "latest")
print(f"Media type: {manifest.media_type}")
print(f"Digest: {manifest.digest}")

# Download blob
blob = client.download_blob("my-image", "sha256:abc123...")
with open("layer.tar.gz", "wb") as f:
    for chunk in blob:
        f.write(chunk)
```

## Async Client

```python
from azure.containerregistry.aio import ContainerRegistryClient
from azure.identity.aio import DefaultAzureCredential

async def list_repos():
    credential = DefaultAzureCredential()
    client = ContainerRegistryClient(endpoint, credential)
    
    async for repo in client.list_repository_names():
        print(repo)
    
    await client.close()
    await credential.close()
```

## Clean Up Old Images

```python
from datetime import datetime, timedelta, timezone

cutoff = datetime.now(timezone.utc) - timedelta(days=30)

for manifest in client.list_manifest_properties("my-image"):
    if manifest.last_updated_on < cutoff and not manifest.tags:
        print(f"Deleting {manifest.digest}")
        client.delete_manifest("my-image", manifest.digest)
```

## Client Operations

| Operation | Description |
|-----------|-------------|
| `list_repository_names` | List all repositories |
| `get_repository_properties` | Get repository metadata |
| `delete_repository` | Delete repository and all images |
| `li
