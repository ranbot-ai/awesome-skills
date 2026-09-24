---
name: dali-short-address-commissioner
description: Commissions DALI and DALI-2 (IEC 62386) lighting buses: short-address assignment (0-63), 24-bit binary search collision resolution, groups, and DT8 color control. Trigger phrases: commission dali, dal
category: Creative & Media
source: antigravity
tags: [python, claude, ai, automation, workflow, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dali-short-address-commissioner
---


# DALI Short-Address Commissioner: Deterministic IEC 62386 Bus Provisioning

Systematically discover, resolve address collisions, assign short addresses (0–63), program groups and scenes, configure DT8 color gear, and schedule emergency battery duration tests on DALI and DALI-2 networks per IEC 62386.

## When to Use This Skill

Activate this skill when:
- Bringing up, commissioning, or expanding DALI or DALI-2 lighting installations (KNX/DALI gateways, Tridonic, Philips Dynalite, Helvar, Osram, Lunatone).
- The user asks: "How do I commission this DALI bus?", "Fix duplicate DALI short addresses", "Assign DALI addresses without erasing existing fixtures", or "Program DALI groups and DT8 tunable white".
- Resolving address clash loops where multiple ballasts respond simultaneously to broadcast queries.
- Designing or scheduling DALI-2 Part 202 emergency lighting duration and function tests across staggered floor circuits.

Do NOT use this skill when:
- Commissioning DMX512/RDM stage lighting, 0–10V analog dimming, or proprietary wireless RF networks (Zigbee, Bluetooth Mesh, Casambi).
- Diagnosing dead ballasts or physical wiring faults before basic DALI bus voltage (12V–20.5V DC) and current limits (<= 250mA) are confirmed.
- Programming building-wide KNX logic (this skill covers the DALI protocol domain strictly).

## Core Mental Models & Non-Negotiable Rules

1. **The 64-Address Bus Capacity Law**:
   - A single DALI subnet supports strictly **0 to 63 short addresses** (64 control gear units maximum).
   - Groups are strictly bounded to **0 to 15** (16 groups).
   - Scenes are strictly bounded to **0 to 15** (16 scenes).
   - If an installation has 65+ ballasts, the physical bus MUST be segmented into multiple DALI subnets with separate line masters or gateways.

2. **The Double-Command 100ms Transmission Invariant**:
   - Configuration and addressing commands (INITIALISE [cmd 258], RANDOMISE [259], SET SHORT ADDRESS [267], ENABLE WRITE [cmd 32], etc.) MUST be transmitted **twice within 100ms** to be executed by control gear.
   - Sending an addressing command only once will result in silent ignored execution by all IEC 62386 compliant gear.

3. **The 15-Minute Hardware Commissioning Timer**:
   - Transmitting `INITIALISE` (cmd 258) starts a mandatory 15-minute countdown timer inside every ballast's micro-controller.
   - All discovery, random address binary searching, and short address assignment MUST complete within 15 minutes, or the bus must receive a periodic keep-alive `INITIALISE` refresh.
   - Upon completion, the master MUST transmit `TERMINATE` (cmd 257) to lock operational memory and exit programming state.

4. **24-Bit Random Address Binary Search ($2^{24} = 16,777,216$ Space)**:
   - When gear enters randomizing state (`RANDOMISE`), each unit generates a pseudo-random 24-bit integer (`0x000000` to `0xFFFFFF`).
   - The master searches the 24-bit space using `SEARCHADDRH`, `SEARCHADDRM`, `SEARCHADDRL` and `COMPARE` (cmd 265).
   - If multiple ballasts match, the master performs binary search down to a single device.
   - Once isolated, assign short address via `PROGRAM SHORT ADDRESS` (cmd 267) and immediately transmit `WITHDRAW` (cmd 266) so the addressed fixture drops out of remaining search iterations.

5. **Physical Identify & Non-Destructive Extension Invariant**:
   - Every assigned short address MUST be verified visually using `IDENTIFY` or toggling `RECALL MAX LEVEL` / `OFF` before committing to lighting schedules.
   - When adding fixtures to an existing operational line, NEVER broadcast a global `INITIALISE (all)`; use `INITIALISE (without short address)` so already-commissioned ballasts (0–63) preserve their programming.

## Named Sins & Anti-Patterns (Что категорически ЗАПРЕЩЕНО)

| Anti-Pattern | Manifestation in Code/Workflow | Mandatory Production Counter-Rule |
| :--- | :--- | :--- |
| **Single-Shot Addressing Commands** | Sending cmd 258 or cmd 267 once without repetition. | Always repeat configuration commands within a strict 100ms window. |
| **Exceeding 64 Short Addresses** | Attempting to assign address 64 or 65 on one loop. | Partition into Subnet A and Subnet B; enforce 0–63 maximum. |
| **Timer Starvation** | Letting the 15-minute `INITIALISE` window expire mid-search. | Issue keep-alive refresh or optimize binary search loop to < 3 minutes. |
| **Ghost Address Overwrite** | Assigning address 0 without scanning if address 0 is in use. | Run non-destructive `QUERY STATUS` (cmd 144) across 0–63 before reassigning. |
| **Bus Overcurrent Overload** | Connecting 64 ballasts (2mA each) + sensors to a 100mA PSU. | Verify total quiescent load $\le$ PSU rating (250mA max per IEC 62386). |
| **DT8 / DT6 Type Mismatch** | Controlling tunable white gear with single-channel DT6 arc power. | Issue `SELECT DIMMING CURVE / COLOUR` (Part 209) and send DT8 color coordinates. |
| **Simultaneous Emergency Discharge** | Triggering 3-hour duration tests on all emergency lights at once. | Stag
