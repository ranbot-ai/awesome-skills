---
name: ebpf-observability
description: Use eBPF for deep kernel-level observability — trace syscalls, network flows, and application behavior without code changes using Cilium, Tetragon, and bpftrace. 
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, template, security, kubernetes, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ebpf-observability
---


# eBPF Observability

eBPF (extended Berkeley Packet Filter) allows you to run sandboxed programs in the Linux kernel without modifying kernel source code or loading kernel modules. This skill covers using eBPF for deep observability, network monitoring, and security enforcement across cloud-native infrastructure.

---

## 2. Prerequisites

### Kernel Version Requirements

| Feature                  | Minimum Kernel | Recommended Kernel |
|--------------------------|----------------|--------------------|
| Basic BPF maps & probes  | 4.9            | 5.10+              |
| BPF CO-RE (BTF support)  | 5.2            | 5.10+              |
| BPF ring buffer          | 5.8            | 5.10+              |
| BPF LSM hooks            | 5.7            | 5.15+              |
| Cilium full features     | 4.19           | 5.10+              |
| Tetragon                 | 4.19           | 5.13+              |

### Verify Kernel Support

```bash
# Check kernel version
uname -r

# Verify BTF (BPF Type Format) is enabled -- required for CO-RE
ls /sys/kernel/btf/vmlinux

# Check BPF filesystem is mounted
mount | grep bpf

# If not mounted, mount it
sudo mount -t bpf bpf /sys/fs/bpf

# Verify BPF JIT is enabled
cat /proc/sys/net/core/bpf_jit_enable
# Should return 1; if not:
sudo sysctl net.core.bpf_jit_enable=1
```

### Install Toolchain

```bash
# Ubuntu/Debian -- install bpftrace, bcc tools, and libbpf
sudo apt-get update
sudo apt-get install -y bpftrace bpfcc-tools libbpf-dev linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install -y bpftrace bcc-tools libbpf-devel kernel-devel

# Verify bpftrace works
sudo bpftrace -e 'BEGIN { printf("eBPF is working\n"); exit(); }'
```

---

## 3. Cilium Setup

Cilium can optionally replace kube-proxy when configured for the cluster, providing identity-aware security and deep network observability via Hubble.

### Install Cilium on Kubernetes

```bash
# Add the Cilium Helm repo
helm repo add cilium https://helm.cilium.io/
helm repo update

# Install Cilium with Hubble enabled
helm install cilium cilium/cilium --version 1.16.4 \
  --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="${API_SERVER_IP}" \
  --set k8sServicePort="${API_SERVER_PORT}" \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.metrics.enableOpenMetrics=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,source_workload\,destination_ip\,destination_namespace\,destination_workload}"

# Wait for Cilium to be ready
cilium status --wait
```

### Install the Cilium CLI and Hubble CLI

```bash
# Install reviewed platform-specific Cilium/Hubble CLI releases through the current official process.
# Verify checksums/signatures and archive members before extraction into a private staging directory.
# Do not extract unverified latest archives directly into /usr/local/bin.
```

### Hubble Network Observability

```bash
# Port-forward the Hubble Relay
cilium hubble port-forward &

# Observe all flows in real time
hubble observe --follow

# Filter flows by namespace
hubble observe --namespace production --follow

# Filter by verdict (dropped traffic)
hubble observe --verdict DROPPED --follow

# Filter by DNS queries
hubble observe --protocol DNS --follow

# Filter HTTP traffic to a specific service
hubble observe --to-label "app=api-server" --protocol HTTP --follow

# Export flows as JSON for ingestion into SIEM
hubble observe --output json --last 1000 > flows.json
```

### Hubble UI Access

```bash
# Port-forward the Hubble UI
kubectl port-forward -n kube-system svc/hubble-ui 12000:80

# Access at http://localhost:12000 -- provides a real-time service dependency map
```

---

## 4. Tetragon for Security

Tetragon is Cilium's runtime security enforcement engine. It uses eBPF to observe and enforce security policies at the kernel level with zero application changes.

### Install Tetragon

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.grpc.enabled=true \
  --set tetragon.exportFilename=/var/run/cilium/tetragon/tetragon.log

# Install a pinned reviewed tetra CLI using verified release artifacts and a private staging directory.
```

### Process Execution Monitoring

```yaml
# process-monitor.yaml -- TracingPolicy to monitor all process executions
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: process-execution-monitor
spec:
  kprobes: []
  tracepoints: []
  uprobes: []
  enforcers: []
  # process_exec and process_exit events are always emitted by default
  # Use tetra CLI to observe them:
```

```bash
# Watch all process executions cluster-wide
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --process-exec

# Filter to a specific namespace
kubectl exec -n kube-system ds/tetragon -c
