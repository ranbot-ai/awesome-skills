---
name: gcp-networking
description: Configure VPCs, firewall rules, and Cloud NAT. Implement shared VPC and private service connect. Use when designing GCP network infrastructure. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, template, design, security, gcp]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gcp-networking
---


# GCP Networking

Design, implement, and secure network infrastructure on Google Cloud Platform.

## When to Use

- Building VPC networks for new GCP projects or multi-project architectures
- Configuring firewall rules to control traffic between services
- Setting up Cloud NAT for outbound internet access from private instances
- Deploying load balancers for HTTP(S), TCP/UDP, or internal traffic
- Implementing Private Service Connect or Shared VPC

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and authenticated
- Compute Engine API enabled
- IAM role `roles/compute.networkAdmin` for network management

```bash
gcloud services enable compute.googleapis.com servicenetworking.googleapis.com
```

## VPC Network Creation

```bash
gcloud compute networks create prod-vpc \
  --subnet-mode=custom --bgp-routing-mode=regional --mtu=1460

gcloud compute networks subnets create us-subnet \
  --network=prod-vpc --region=us-central1 --range=10.0.0.0/20 \
  --enable-private-ip-google-access --enable-flow-logs \
  --logging-flow-sampling=0.5

gcloud compute networks subnets create eu-subnet \
  --network=prod-vpc --region=europe-west1 --range=10.1.0.0/20 \
  --enable-private-ip-google-access --enable-flow-logs

# Subnet with secondary ranges for GKE
gcloud compute networks subnets create gke-subnet \
  --network=prod-vpc --region=us-central1 --range=10.2.0.0/20 \
  --secondary-range=pods=10.4.0.0/14,services=10.8.0.0/20 \
  --enable-private-ip-google-access

# Proxy-only subnet (required for regional L7 LBs)
gcloud compute networks subnets create proxy-only-subnet \
  --network=prod-vpc --region=us-central1 --range=10.129.0.0/23 \
  --purpose=REGIONAL_MANAGED_PROXY --role=ACTIVE
```

## Firewall Rules

```bash
gcloud compute firewall-rules create allow-http-https \
  --network=prod-vpc --allow=tcp:80,tcp:443 \
  --source-ranges=0.0.0.0/0 --target-tags=http-server --priority=1000

gcloud compute firewall-rules create allow-internal \
  --network=prod-vpc --allow=tcp,udp,icmp \
  --source-ranges=10.0.0.0/8 --priority=1000

gcloud compute firewall-rules create allow-iap-ssh \
  --network=prod-vpc --allow=tcp:22 \
  --source-ranges=35.235.240.0/20 --priority=1000

gcloud compute firewall-rules create allow-health-checks \
  --network=prod-vpc --allow=tcp:80,tcp:443,tcp:8080 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --target-tags=http-server --priority=900

# List firewall rules
gcloud compute firewall-rules list --filter="network=prod-vpc" \
  --format="table(name,direction,priority,allowed[].map().firewall_rule().list():label=ALLOW)"
```

## Cloud NAT

```bash
gcloud compute routers create prod-router \
  --network=prod-vpc --region=us-central1

gcloud compute routers nats create prod-nat \
  --router=prod-router --region=us-central1 \
  --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips \
  --min-ports-per-vm=256 --max-ports-per-vm=4096 \
  --enable-logging --log-filter=ERRORS_ONLY

# Static NAT IPs (stable egress)
gcloud compute addresses create nat-ip-1 nat-ip-2 --region=us-central1
gcloud compute routers nats create prod-nat-static \
  --router=prod-router --region=us-central1 \
  --nat-all-subnet-ip-ranges --nat-external-ip-pool=nat-ip-1,nat-ip-2
```

## External HTTP(S) Load Balancer

```bash
gcloud compute addresses create web-lb-ip --global

gcloud compute health-checks create http web-hc \
  --port=80 --request-path=/healthz --check-interval=10s --timeout=5s

gcloud compute backend-services create web-backend \
  --protocol=HTTP --port-name=http --health-checks=web-hc \
  --global --enable-cdn --enable-logging

gcloud compute backend-services add-backend web-backend \
  --instance-group=web-mig --instance-group-region=us-central1 \
  --balancing-mode=UTILIZATION --max-utilization=0.8 --global

gcloud compute url-maps create web-url-map --default-service=web-backend

gcloud compute ssl-certificates create web-cert \
  --domains=app.example.com --global

gcloud compute target-https-proxies create web-proxy \
  --url-map=web-url-map --ssl-certificates=web-cert

gcloud compute forwarding-rules create web-https \
  --address=web-lb-ip --target-https-proxy=web-proxy --ports=443 --global
```

## Internal Load Balancer

```bash
gcloud compute backend-services create internal-backend \
  --protocol=TCP --region=us-central1 \
  --health-checks=web-hc --health-checks-region=us-central1 \
  --load-balancing-scheme=INTERNAL

gcloud compute forwarding-rules create internal-lb \
  --region=us-central1 --load-balancing-scheme=INTERNAL \
  --network=prod-vpc --subnet=us-subnet \
  --backend-service=internal-backend --ports=8080
```

## Cloud Armor (DDoS and WAF)

```bash
gcloud compute security-policies create web-armor

gcloud compute security-policies rules create 1000 \
  --security-policy=web-armor \
  --expression="origin.region_code == 'XX'" --action=deny-403

gcloud compute security-policies rules create 2000 \
  --security-policy=web-armor --expression="true" \
  --action=rate-based-ban \
  --
