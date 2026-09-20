---
name: gcp-secret-manager
description: Secure secrets in Google Cloud Secret Manager. Configure IAM policies, integrate with GKE, and manage secret versions. Use when managing secrets in GCP environments. 
category: AI & Agents
source: antigravity
tags: [python, javascript, node, api, ai, agent, template, image, security, kubernetes]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-secret-manager
---


# GCP Secret Manager

Store and manage secrets securely in Google Cloud Platform.

## Prerequisites

- GCP project with billing enabled
- `gcloud` CLI installed and authenticated
- Secret Manager API enabled (`secretmanager.googleapis.com`)
- IAM permissions: `roles/secretmanager.admin` for management, `roles/secretmanager.secretAccessor` for reading
- For GKE: Workload Identity configured on the cluster

## Enable the API

```bash
# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com

# Verify it's enabled
gcloud services list --enabled --filter="name:secretmanager"
```

## Secret Creation and Management

```bash
# Create a secret (creates the secret resource, not the value)
gcloud secrets create db-password \
  --replication-policy="automatic" \
  --labels="env=production,team=platform"

# Add the secret value (first version)
echo -n "S3cur3P@ssw0rd!" | gcloud secrets versions add db-password --data-file=-

# Create secret with value in one command
echo -n '{"username":"dbadmin","password":"S3cur3P@ss!","host":"10.0.1.5","port":5432}' | \
  gcloud secrets create db-credentials --data-file=- \
  --replication-policy="automatic" \
  --labels="env=production,team=platform"

# Create with specific region replication
gcloud secrets create regional-secret \
  --replication-policy="user-managed" \
  --locations="us-central1,us-east1"

# Create with customer-managed encryption key (CMEK)
gcloud secrets create sensitive-secret \
  --replication-policy="user-managed" \
  --locations="us-central1" \
  --kms-key-name="projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key"

# Access the latest version
gcloud secrets versions access latest --secret=db-password

# Access a specific version
gcloud secrets versions access 3 --secret=db-password

# Add a new version (rotation)
echo -n "N3wS3cur3P@ss!" | gcloud secrets versions add db-password --data-file=-

# List all secrets
gcloud secrets list --format="table(name, createTime, labels)"

# List versions of a secret
gcloud secrets versions list db-password --format="table(name, state, createTime)"

# Disable a version (makes it inaccessible but recoverable)
gcloud secrets versions disable 1 --secret=db-password

# Enable a disabled version
gcloud secrets versions enable 1 --secret=db-password

# Destroy a version (permanent)
gcloud secrets versions destroy 1 --secret=db-password

# Delete the entire secret
gcloud secrets delete db-password

# Set expiration on a secret
gcloud secrets update db-password \
  --expire-time="2026-06-01T00:00:00Z"

# Set TTL-based expiration
gcloud secrets update temp-token \
  --ttl="2592000s"  # 30 days

# Update labels
gcloud secrets update db-password \
  --update-labels="rotation=enabled,last-rotated=2025-01-15"

# Add version aliases
gcloud secrets versions update 5 --secret=db-password --set-aliases="production"
```

## IAM Bindings

```bash
# Grant secret accessor role to a service account
gcloud secrets add-iam-policy-binding db-password \
  --member="serviceAccount:myapp-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Grant access to a specific secret version
gcloud secrets add-iam-policy-binding db-password \
  --member="serviceAccount:myapp-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretVersionAccessor" \
  --condition='expression=resource.name.endsWith("versions/latest"),title=latest-only'

# Grant admin to security team
gcloud secrets add-iam-policy-binding db-password \
  --member="group:security-team@example.com" \
  --role="roles/secretmanager.admin"

# View IAM policy for a secret
gcloud secrets get-iam-policy db-password

# Remove access
gcloud secrets remove-iam-policy-binding db-password \
  --member="serviceAccount:old-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Project-level IAM for all secrets
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:myapp-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" \
  --condition='expression=resource.name.startsWith("projects/my-project/secrets/myapp-"),title=myapp-secrets-only'
```

## Workload Identity for GKE

```bash
# Enable Workload Identity on cluster (if not already)
gcloud container clusters update my-cluster \
  --zone us-central1-a \
  --workload-pool=my-project.svc.id.goog

# Create GCP service account for the workload
gcloud iam service-accounts create myapp-gke-sa \
  --display-name="MyApp GKE Service Account"

# Grant secret accessor role
gcloud secrets add-iam-policy-binding db-password \
  --member="serviceAccount:myapp-gke-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Bind Kubernetes SA to GCP SA
gcloud iam service-accounts add-iam-policy-binding \
  myapp-gke-sa@my-project.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:my-project.svc.id.goog[produ
