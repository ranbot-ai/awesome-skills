---
name: Wireshark Network Traffic Analysis
description: This skill should be used when the user asks to "analyze network traffic with Wireshark", "capture packets for troubleshooting", "filter PCAP files", "follow TCP/UDP streams", "detect network anomalie
category: Document Processing
source: antigravity
tags: [ai, workflow, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/wireshark-analysis
---


# Wireshark Network Traffic Analysis

## Purpose

Execute comprehensive network traffic analysis using Wireshark to capture, filter, and examine network packets for security investigations, performance optimization, and troubleshooting. This skill enables systematic analysis of network protocols, detection of anomalies, and reconstruction of network conversations from PCAP files.

## Inputs / Prerequisites

### Required Tools
- Wireshark installed (Windows, macOS, or Linux)
- Network interface with capture permissions
- PCAP/PCAPNG files for offline analysis
- Administrator/root privileges for live capture

### Technical Requirements
- Understanding of network protocols (TCP, UDP, HTTP, DNS)
- Familiarity with IP addressing and ports
- Knowledge of OSI model layers
- Understanding of common attack patterns

### Use Cases
- Network troubleshooting and connectivity issues
- Security incident investigation
- Malware traffic analysis
- Performance monitoring and optimization
- Protocol learning and education

## Outputs / Deliverables

### Primary Outputs
- Filtered packet captures for specific traffic
- Reconstructed communication streams
- Traffic statistics and visualizations
- Evidence documentation for incidents

## Core Workflow

### Phase 1: Capturing Network Traffic

#### Start Live Capture
Begin capturing packets on network interface:

```
1. Launch Wireshark
2. Select network interface from main screen
3. Click shark fin icon or double-click interface
4. Capture begins immediately
```

#### Capture Controls
| Action | Shortcut | Description |
|--------|----------|-------------|
| Start/Stop Capture | Ctrl+E | Toggle capture on/off |
| Restart Capture | Ctrl+R | Stop and start new capture |
| Open PCAP File | Ctrl+O | Load existing capture file |
| Save Capture | Ctrl+S | Save current capture |

#### Capture Filters
Apply filters before capture to limit data collection:

```
# Capture only specific host
host 192.168.1.100

# Capture specific port
port 80

# Capture specific network
net 192.168.1.0/24

# Exclude specific traffic
not arp

# Combine filters
host 192.168.1.100 and port 443
```

### Phase 2: Display Filters

#### Basic Filter Syntax
Filter captured packets for analysis:

```
# IP address filters
ip.addr == 192.168.1.1              # All traffic to/from IP
ip.src == 192.168.1.1               # Source IP only
ip.dst == 192.168.1.1               # Destination IP only

# Port filters
tcp.port == 80                       # TCP port 80
udp.port == 53                       # UDP port 53
tcp.dstport == 443                   # Destination port 443
tcp.srcport == 22                    # Source port 22
```

#### Protocol Filters
Filter by specific protocols:

```
# Common protocols
http                                  # HTTP traffic
https or ssl or tls                   # Encrypted web traffic
dns                                   # DNS queries and responses
ftp                                   # FTP traffic
ssh                                   # SSH traffic
icmp                                  # Ping/ICMP traffic
arp                                   # ARP requests/responses
dhcp                                  # DHCP traffic
smb or smb2                          # SMB file sharing
```

#### TCP Flag Filters
Identify specific connection states:

```
tcp.flags.syn == 1                   # SYN packets (connection attempts)
tcp.flags.ack == 1                   # ACK packets
tcp.flags.fin == 1                   # FIN packets (connection close)
tcp.flags.reset == 1                 # RST packets (connection reset)
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN-only (initial connection)
```

#### Content Filters
Search for specific content:

```
frame contains "password"            # Packets containing string
http.request.uri contains "login"    # HTTP URIs with string
tcp contains "GET"                   # TCP packets with string
```

#### Analysis Filters
Identify potential issues:

```
tcp.analysis.retransmission          # TCP retransmissions
tcp.analysis.duplicate_ack           # Duplicate ACKs
tcp.analysis.zero_window             # Zero window (flow control)
tcp.analysis.flags                   # Packets with issues
dns.flags.rcode != 0                 # DNS errors
```

#### Combining Filters
Use logical operators for complex queries:

```
# AND operator
ip.addr == 192.168.1.1 && tcp.port == 80

# OR operator
dns || http

# NOT operator
!(arp || icmp)

# Complex combinations
(ip.src == 192.168.1.1 || ip.src == 192.168.1.2) && tcp.port == 443
```

### Phase 3: Following Streams

#### TCP Stream Reconstruction
View complete TCP conversation:

```
1. Right-click on any TCP packet
2. Select Follow > TCP Stream
3. View reconstructed conversation
4. Toggle between ASCII, Hex, Raw views
5. Filter to show only this stream
```

#### Stream Types
| Stream | Access | Use Case |
|--------|--------|----------|
| TCP Stream | Follow > TCP Stream | Web, file transfers, any TCP |
| UDP Stream | Follow > UDP Str
