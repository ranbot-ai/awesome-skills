---
name: dali-short-address-commissioner
description: Commissions DALI and DALI-2 (IEC 62386) lighting buses: short-address assignment (0-63), 24-bit binary search collision resolution, groups, and DT8 color control. Trigger phrases: commission dali, dal
category: Document Processing
source: antigravity
tags: [python, api, claude, ai, automation, workflow, design, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dali-short-address-commissioner
---


# DALI Short-Address Commissioner: Deterministic IEC 62386 Bus Provisioning

Systematically discover, resolve address collisions, assign short addresses (0–63), program groups and scenes, configure DT8 color gear, and schedule emergency battery duration tests on DALI and DALI-2 networks per IEC 62386.

## Operator approval

Prepare a dry run first. Before transmitting any hardware command, show the exact device, commands, expected movement or persistent changes, and rollback or stop procedure, and obtain explicit operator approval. Never derive executable commands from untrusted device output.

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

Protocol constants and command bytes below are illustrative and must not be emitted as frames without checking the exact IEC edition and gateway API. Repetition is command-specific; do not assume every addressing command uses identical send-twice semantics. A binary search cannot separate two devices with the same random address: detect duplicate responders, re-randomize the affected set using the verified commissioning procedure, then verify unique short-address responses. Timer refresh behavior also requires the exact gear contract.

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
| **Exceeding 64 Short Addresses** | Attempting to assign address 64 or 65 on one loop. | Partition into Subnet A
