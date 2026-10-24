---
name: bb-methodology
description: Use at the START of any bug bounty hunting session, when switching targets, or when feeling lost about what to do next. 
category: Security & Systems
source: antigravity
tags: [python, pdf, api, claude, ai, automation, workflow, template, design, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/bb-methodology
---

> **⚠️ AUTHORIZED USE ONLY**
> This skill is for educational purposes or authorized security assessments only.
> You must have explicit, written permission from the system owner before using this tool.
> Misuse of this tool is illegal and strictly prohibited.

> **Mandatory confirmation gate**
> Before running any command that probes, exploits, changes, persists on, extracts data from, or attempts credential access against a target:
> 1. Ask the user to state the exact target URL, IP, account, or resource.
> 2. Ask the user to confirm written authorization and the permitted scope.
> 3. Show the exact command(s) and explain their expected effect.
> 4. Wait for explicit confirmation in the current conversation.
>
> Without that confirmation, remain read-only and provide defensive guidance only. Prefer a sandbox, disposable VM, or controlled lab.

# Bug Bounty Methodology: Workflow + Mindset

A planning framework for authorized assessment sessions. It provides no measured top-percentile performance guarantee.

---

## Scope and evidence boundary

Follow the actual written program/SoW, scoped assets, testing methods, request/concurrency limits and stop conditions. Newly discovered assets, origin IPs and third-party integrations are not automatically in scope. Slash commands and linked skills are external dependencies, not bundled functions. Do not automatically install or execute them. Imported anecdotes/test counts are not independently verified by this bundle.

## PART 0: MODE CONFIRMATION (Before Anything Else)

**Confirm the engagement type before deciding what counts as a finding.** The same target produces a different report shape depending on which mode applies. Getting this wrong is the single biggest waste of time in this workflow — answer it explicitly before Phase 0.

| Engagement type | What counts as a finding | What gets rejected |
|---|---|---|
| **Bug bounty** (H1 / Bugcrowd / Intigriti / private VDP) | Impact-demonstrated bugs ONLY. Full chain to attacker-attainable harm. | Eligibility depends on the actual program; hygiene or disclosure may be accepted when its policy allows it |
| **Red team** (external client engagement) | Hygiene findings + recon + IoCs + defensive-state observations are ALL deliverables | Deliverables depend on the rules of engagement; a negative test is an observation under stated conditions, not security certification |
| **Pentest** (signed SoW / WAPT) | Depends on SoW. Read scope explicitly. Usually accepts hygiene + impact + recon | Out-of-scope assets, unsigned testing |
| **Internal audit** | Compliance-mapped findings (PCI / ISO / NIST / DPDPA / GDPR) | Findings without a control-mapping |

**Hard rule:** Before Phase 0 runs, write the engagement type as the first line in your hunt notes. If you can't answer it from the user's instruction, ASK once. Don't assume — the mistake costs both you and the triager.

**Lesson from an authorized engagement:** First-pass on this target produced 5 hygiene findings (SP2013 EoL, permissive CSP, stack traces) shipped in red-team format. The engagement was bug-bounty. Findings would have been N/A'd as "informational, no impact demonstrated." After the corrected pass with hygiene-as-context-not-finding, the same target yielded 11 impact-demonstrated bugs including 3 Critical.

---

## PART 1: MINDSET (How to Think)

### Core Principle

Hunting is not "find a bug" -- it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

### Daily Discipline: Define, Select, Execute

Before touching any tool:

1. **Define**: "Today I target [feature/domain] to achieve [CIA impact]"
2. **Select**: Choose 1-2 vuln classes (IDOR, Race Condition, etc.)
3. **Execute**: Focus ONLY on selected techniques. No wandering.

### 5 Ultimate Goals (Pick One Per Session)

1. **Confidentiality** -- steal data the attacker shouldn't see
2. **Integrity** -- modify data the attacker shouldn't change
3. **Availability** -- evaluate resilience only if explicitly permitted; app-level DoS is still disruptive
4. **Account Takeover** -- control another user's account
5. **RCE** -- execute commands on the server

### 4 Thinking Domains

#### 1. Critical Thinking (deep analysis)

**Question trust boundaries:**
- Frontend control disabled? Send request directly via proxy
- `user_role=user` cookie? Change to `admin`
- `price=1000` in POST? Change to `1`
- `<script>` blocked? Try `<img onerror=...>`

**Reverse-engineer developer psychology:**
- Feature A has auth checks -> Similar feature B (newly added) probably doesn't
- Complex flows (coupon + points + refund) -> Edge cases have bugs
- `/api/v2/user` exists -> Does `/api/v1/user` still work with weaker auth?

**What-If experiments:**
- Skip checkout -> hit `/checkout/success` directly
- Skip 2FA -> navigate to `/dashboard`
- Send coupon request 10x simultaneously -> Race condition?
- Replace `guid=f8a2...` with `id=100` on sibling endpoint -> IDOR?

#### 2. Multi-Pe
