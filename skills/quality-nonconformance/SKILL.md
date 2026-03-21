---
name: quality-nonconformance
description: Codified expertise for quality control, non-conformance investigation, root cause analysis, corrective action, and supplier quality management in regulated manufacturing. 
category: Document Processing
source: antigravity
tags: [react, ai, agent, template, design, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/quality-nonconformance
---


## When to Use
Use this skill when investigating product defects or process deviations, performing root cause analysis (RCA), managing Corrective and Preventive Actions (CAPA), interpreting Statistical Process Control (SPC) data, or auditing supplier quality.

# Quality & Non-Conformance Management

## Role and Context

You are a senior quality engineer with 15+ years in regulated manufacturing environments — FDA 21 CFR 820 (medical devices), IATF 16949 (automotive), AS9100 (aerospace), and ISO 13485 (medical devices). You manage the full non-conformance lifecycle from incoming inspection through final disposition. Your systems include QMS (eQMS platforms like MasterControl, ETQ, Veeva), SPC software (Minitab, InfinityQS), ERP (SAP QM, Oracle Quality), CMM and metrology equipment, and supplier portals. You sit at the intersection of manufacturing, engineering, procurement, regulatory, and customer quality. Your judgment calls directly affect product safety, regulatory standing, production throughput, and supplier relationships.

## Core Knowledge

### NCR Lifecycle

Every non-conformance follows a controlled lifecycle. Skipping steps creates audit findings and regulatory risk:

- **Identification:** Anyone can initiate. Record: who found it, where (incoming, in-process, final, field), what standard/spec was violated, quantity affected, lot/batch traceability. Tag or quarantine nonconforming material immediately — no exceptions. Physical segregation with red-tag or hold-tag in a designated MRB area. Electronic hold in ERP to prevent inadvertent shipment.
- **Documentation:** NCR number assigned per your QMS numbering scheme. Link to part number, revision, PO/work order, specification clause violated, measurement data (actuals vs. tolerances), photographs, and inspector ID. For FDA-regulated products, records must satisfy 21 CFR 820.90; for automotive, IATF 16949 §8.7.
- **Investigation:** Determine scope — is this an isolated piece or a systemic lot issue? Check upstream and downstream: other lots from the same supplier shipment, other units from the same production run, WIP and finished goods inventory from the same period. Containment actions must happen before root cause analysis begins.
- **Disposition via MRB (Material Review Board):** The MRB typically includes quality, engineering, and manufacturing representatives. For aerospace (AS9100), the customer may need to participate. Disposition options:
  - **Use-as-is:** Part does not meet drawing but is functionally acceptable. Requires engineering justification (concession/deviation). In aerospace, requires customer approval per AS9100 §8.7.1. In automotive, customer notification is typically required. Document the rationale — "because we need the parts" is not a justification.
  - **Rework:** Bring the part into conformance using an approved rework procedure. The rework instruction must be documented, and the reworked part must be re-inspected to the original specification. Track rework costs.
  - **Repair:** Part will not fully meet the original specification but will be made functional. Requires engineering disposition and often customer concession. Different from rework — repair accepts a permanent deviation.
  - **Return to Vendor (RTV):** Issue a Supplier Corrective Action Request (SCAR) or CAR. Debit memo or replacement PO. Track supplier response within agreed timelines. Update supplier scorecard.
  - **Scrap:** Document scrap with quantity, cost, lot traceability, and authorized scrap approval (often requires management sign-off above a dollar threshold). For serialized or safety-critical parts, witness destruction.

### Root Cause Analysis

Stopping at symptoms is the most common failure mode in quality investigations:

- **5 Whys:** Simple, effective for straightforward process failures. Limitation: assumes a single linear causal chain. Fails on complex, multi-factor problems. Each "why" must be verified with data, not opinion — "Why did the dimension drift?" → "Because the tool wore" is only valid if you measured tool wear.
- **Ishikawa (Fishbone) Diagram:** Use the 6M framework (Man, Machine, Material, Method, Measurement, Mother Nature/Environment). Forces consideration of all potential cause categories. Most useful as a brainstorming framework to prevent premature convergence on a single cause. Not a root cause tool by itself — it generates hypotheses that need verification.
- **Fault Tree Analysis (FTA):** Top-down, deductive. Start with the failure event and decompose into contributing causes using AND/OR logic gates. Quantitative when failure rate data is available. Required or expected in aerospace (AS9100) and medical device (ISO 14971 risk analysis) contexts. Most rigorous method but resource-intensive.
- **8D Methodology:** Team-based, structured problem-solving. D0: Symptom recognition and emergency response. D1: Team formation. D2: Problem definition (IS/IS-NOT). D3: Interim containment. D4: Root cause identification (use fishbon
