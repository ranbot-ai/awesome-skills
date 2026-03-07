---
name: clarity-gate
description: Pre-ingestion verification for epistemic quality in RAG systems. Ensures documents are properly qualified before entering knowledge bases. Produces CGD (Clarity-Gated Documents) and validates SOT (Sou
category: AI & Agents
source: antigravity
tags: [python, markdown, api, claude, ai, agent, llm, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/clarity-gate
---


# Clarity Gate v2.1

**Purpose:** Pre-ingestion verification system that enforces epistemic quality before documents enter RAG knowledge bases. Produces Clarity-Gated Documents (CGD) compliant with the Clarity Gate Format Specification v2.1.

**Core Question:** "If another LLM reads this document, will it mistake assumptions for facts?"

**Core Principle:** *"Detection finds what is; enforcement ensures what should be. In practice: find the missing uncertainty markers before they become confident hallucinations."*

---

## What's New in v2.1

| Feature | Description |
|---------|-------------|
| **Claim Completion Status** | PENDING/VERIFIED determined by field presence (no explicit status field) |
| **Source Field Semantics** | Actionable source (PENDING) vs. what-was-found (VERIFIED) |
| **Claim ID Format Guidance** | Hash-based IDs preferred, collision analysis for scale |
| **Body Structure Requirements** | HITL Verification Record section mandatory when claims exist |
| **New Validation Codes** | E-ST10, W-ST11, W-HC01, W-HC02, E-SC06 (FORMAT_SPEC); E-TB01-07 (SOT validation) |
| **Bundled Scripts** | `claim_id.py` and `document_hash.py` for deterministic computations |

---

## Specifications

This skill implements and references:

| Specification | Version | Location |
|---------------|---------|----------|
| Clarity Gate Format (Unified) | v2.1 | docs/CLARITY_GATE_FORMAT_SPEC.md |

**Note:** v2.0 unifies CGD and SOT into a single `.cgd.md` format. SOT is now a CGD with an optional `tier:` block.

---

## Validation Codes

Clarity Gate defines validation codes for structural and semantic checks per FORMAT_SPEC v2.1:

### HITL Claim Validation (§1.3.2-1.3.3)
| Code | Check | Severity |
|------|-------|----------|
| **W-HC01** | Partial `confirmed-by`/`confirmed-date` fields | WARNING |
| **W-HC02** | Vague source (e.g., "industry reports", "TBD") | WARNING |
| **E-SC06** | Schema error in `hitl-claims` structure | ERROR |

### Body Structure (§1.2.1)
| Code | Check | Severity |
|------|-------|----------|
| **E-ST10** | Missing `## HITL Verification Record` when claims exist | ERROR |
| **W-ST11** | Table rows don't match `hitl-claims` count | WARNING |

### SOT Table Validation (§3.1)
| Code | Check | Severity |
|------|-------|----------|
| **E-TB01** | No `## Verified Claims` section | ERROR |
| **E-TB02** | Table has no data rows | ERROR |
| **E-TB03** | Required columns missing | ERROR |
| **E-TB04** | Column order wrong | ERROR |
| **E-TB05** | Empty cell in required column | ERROR |
| **E-TB06** | Invalid date format in Verified column | ERROR |
| **E-TB07** | Verified date in future (beyond 24h grace) | ERROR |

**Note:** Additional validation codes may be defined in RFC-001 (clarification document) but are not part of the normative FORMAT_SPEC.

---

## Bundled Scripts

This skill includes Python scripts for deterministic computations per FORMAT_SPEC.

### scripts/claim_id.py

Computes stable, hash-based claim IDs for HITL tracking (per §1.3.4).

```bash
# Generate claim ID
python scripts/claim_id.py "Base price is $99/mo" "api-pricing/1"
# Output: claim-75fb137a

# Run test vectors
python scripts/claim_id.py --test
```

**Algorithm:**
1. Normalize text (strip + collapse whitespace)
2. Concatenate with location using pipe delimiter
3. SHA-256 hash, take first 8 hex chars
4. Prefix with "claim-"

**Test vectors:**
- `claim_id("Base price is $99/mo", "api-pricing/1")` → `claim-75fb137a`
- `claim_id("The API supports GraphQL", "features/1")` → `claim-eb357742`

### scripts/document_hash.py

Computes document SHA-256 hash per FORMAT_SPEC §2.2-2.4 with full canonicalization.

```bash
# Compute hash
python scripts/document_hash.py my-doc.cgd.md
# Output: 7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730

# Verify existing hash
python scripts/document_hash.py --verify my-doc.cgd.md
# Output: PASS: Hash verified: 7d865e...

# Run normalization tests
python scripts/document_hash.py --test
```

**Algorithm (per §2.2-2.4):**
1. Extract content between opening `---\n` and `<!-- CLARITY_GATE_END -->`
2. Remove `document-sha256` line from YAML frontmatter ONLY (with multiline continuation support)
3. Canonicalize:
   - Strip trailing whitespace per line
   - Collapse 3+ consecutive newlines to 2
   - Normalize final newline (exactly 1 LF)
   - UTF-8 NFC normalization
4. Compute SHA-256

**Cross-platform normalization:**
- BOM removed if present
- CRLF to LF (Windows)
- CR to LF (old Mac)
- Boundary detection (prevents hash computation on content outside CGD structure)
- Whitespace variations produce identical hashes (deterministic across platforms)

---

## The Key Distinction

Existing tools like UnScientify and HedgeHunter (CoNLL-2010) **detect** uncertainty markers already present in text ("Is uncertainty expressed?").

Clarity Gate **enforces** their presence where epistemically required ("Should uncertainty be expressed but isn't?").

| Tool Type | Question | Example |
|-----------|---
