---
name: gcp-cloud-functions
description: Deploy serverless functions on Google Cloud Functions. Configure triggers and manage deployments. Use when implementing serverless workloads on GCP. 
category: Document Processing
source: antigravity
tags: [python, javascript, react, node, api, ai, agent, template, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-cloud-functions
---


# GCP Cloud Functions

Build and deploy event-driven serverless applications with Google Cloud Functions (Gen1 and Gen2).

## When to Use

- Processing webhooks, API endpoints, or lightweight HTTP backends
- Reacting to events from Pub/Sub, Cloud Storage, Firestore, or Eventarc
- Running scheduled tasks (cron) without maintaining a server
- Building data-processing pipelines triggered by file uploads
- Prototyping microservices before committing to Cloud Run or GKE

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and authenticated
- APIs enabled: Cloud Functions, Cloud Build, Artifact Registry, Cloud Run (Gen2)
- IAM role `roles/cloudfunctions.developer` (or `roles/run.developer` for Gen2)

```bash
gcloud services enable cloudfunctions.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com run.googleapis.com eventarc.googleapis.com
```

## Gen1 vs Gen2 Comparison

| Feature | Gen1 | Gen2 (recommended) |
|---------|------|---------------------|
| Runtime | Cloud Functions infra | Built on Cloud Run |
| Max timeout | 9 minutes | 60 minutes |
| Max memory | 8 GB | 32 GB |
| Concurrency | 1 request/instance | Up to 1000/instance |
| Traffic splitting | No | Yes |
| Eventarc triggers | No | Yes |

## Deploy an HTTP Function (Gen2)

```bash
# Python HTTP function
gcloud functions deploy hello-http \
  --gen2 --region=us-central1 --runtime=python312 \
  --trigger-http --allow-unauthenticated \
  --entry-point=hello_http \
  --memory=256Mi --timeout=60s \
  --min-instances=0 --max-instances=100 \
  --set-env-vars=APP_ENV=production --source=.

# Node.js HTTP function
gcloud functions deploy hello-node \
  --gen2 --region=us-central1 --runtime=nodejs20 \
  --trigger-http --allow-unauthenticated \
  --entry-point=helloNode --memory=256Mi --source=.
```

## Deploy a Pub/Sub Triggered Function

```bash
gcloud pubsub topics create order-events

gcloud functions deploy process-order \
  --gen2 --region=us-central1 --runtime=python312 \
  --trigger-topic=order-events \
  --entry-point=process_order \
  --memory=512Mi --timeout=120s --retry \
  --service-account=order-processor@${PROJECT_ID}.iam.gserviceaccount.com \
  --source=.
```

## Deploy a Cloud Storage Triggered Function

```bash
gcloud functions deploy process-upload \
  --gen2 --region=us-central1 --runtime=python312 \
  --trigger-event-filters="type=google.cloud.storage.object.v1.finalized" \
  --trigger-event-filters="bucket=my-upload-bucket" \
  --entry-point=process_upload \
  --memory=1Gi --timeout=300s --source=.
```

## Deploy a Scheduled Function

```bash
gcloud functions deploy daily-cleanup \
  --gen2 --region=us-central1 --runtime=python312 \
  --trigger-http --no-allow-unauthenticated \
  --entry-point=daily_cleanup --source=.

gcloud scheduler jobs create http daily-cleanup-job \
  --schedule="0 2 * * *" \
  --uri="https://us-central1-${PROJECT_ID}.cloudfunctions.net/daily-cleanup" \
  --http-method=POST \
  --oidc-service-account-email=scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --location=us-central1
```

## Python Function Examples

```python
# main.py
import functions_framework
import base64, json
from flask import jsonify
from google.cloud import firestore

@functions_framework.http
def hello_http(request):
    """HTTP Cloud Function."""
    name = request.args.get("name", "World")
    return jsonify({"message": f"Hello, {name}!", "status": "ok"}), 200

@functions_framework.cloud_event
def process_order(cloud_event):
    """Triggered by a Pub/Sub message."""
    data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    order = json.loads(data)
    db = firestore.Client()
    db.collection("orders").document(order["id"]).set({
        "status": "processing", "items": order["items"], "total": order["total"],
    })

@functions_framework.cloud_event
def process_upload(cloud_event):
    """Triggered when a file is uploaded to Cloud Storage."""
    data = cloud_event.data
    bucket_name, file_name = data["bucket"], data["name"]
    if not file_name.lower().endswith((".png", ".jpg", ".jpeg")):
        return
    from google.cloud import vision
    client = vision.ImageAnnotatorClient()
    image = vision.Image(source=vision.ImageSource(
        gcs_image_uri=f"gs://{bucket_name}/{file_name}"))
    labels = [l.description for l in client.label_detection(image=image).label_annotations]
    print(f"Labels for {file_name}: {labels}")
```

```
# requirements.txt
functions-framework==3.*
google-cloud-firestore==2.*
google-cloud-storage==2.*
google-cloud-vision==3.*
flask>=2.0
```

## Node.js Function Examples

```javascript
// index.js
const functions = require("@google-cloud/functions-framework");

functions.http("helloNode", (req, res) => {
  const name = req.query.name || "World";
  res.json({ message: `Hello, ${name}!`, status: "ok" });
});

functions.cloudEvent("processMessage", (cloudEvent) => {
  const data = Buffer.from(cloudEvent.data.message.data, "base64").toString();
  console.l
