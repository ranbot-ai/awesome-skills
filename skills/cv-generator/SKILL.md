---
name: cv-generator
description: Generate professional, ATS-optimized CVs for FlowCV, Canva, Google Docs, or Word. Handles multi-source merging, JD targeting, seniority adaptation, and humanized rewriting. Outputs paste-ready text wi
category: Document Processing
source: antigravity
tags: [javascript, react, pdf, docx, markdown, api, ai, agent, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cv-generator
---


# CV Generator Skill — FlowCV / Canva Edition

## When to Use

Use this skill when you need to:
- Generate a professional, ATS-optimized CV from multiple sources (LinkedIn, GitHub, Portfolio).
- Tailor an existing CV for a specific Job Description (JD).
- Improve the language, metrics, and structure of a draft resume.
- Prepare a paste-ready version of your CV for tools like FlowCV or Canva.

Turns raw profile data into a polished, ATS-ready CV. Outputs a paste-ready plain-text
version formatted for FlowCV, Canva, Google Docs, or Word — with a flaw report and
missing-info checklist.

---

## FLAW REGISTER — KNOWN ISSUES FIXED IN THIS VERSION

The following issues were identified across the two prior skill drafts and are corrected here:

| # | Flaw | Fix applied |
|---|------|-------------|
| F-01 | Output was Markdown-first, not paste-ready plain text | Final output is plain text; Markdown is internal staging only |
| F-02 | FlowCV/Canva field structure was never addressed | Section mapping to tool fields added (section 11c) |
| F-03 | Questionnaire dumped all 20 questions at once in practice | Hard rule: one question at a time, wait for answer |
| F-04 | Anti-hallucination rules listed but never enforced structurally | Enforcement gate added before every output (section 10) |
| F-05 | Cover letter was offered but never scoped for these tools | Cover letter now outputs to a separate plain-text block, not inline |
| F-06 | ATS check listed but had no scored output | Flaw report now scores 0–100 with per-item pass/fail |
| F-07 | Seniority detection was "detect or ask" with no fallback | Default is mid-level if undetectable; user is told the assumption |
| F-08 | No guidance on what FlowCV/Canva cannot render | Added explicit field-by-field paste map (section 11c) |
| F-09 | Tense rules stated but never verified in quality gate | Tense check is now a hard gate — output blocked until corrected |
| F-10 | "Passionate about" and similar banned phrases still appeared in examples | Phrase blocklist now machine-checkable (section 7c) |
| F-11 | Nepal/South Asia market conventions were present but incomplete | Confirmed and expanded (section 14) |
| F-12 | No explicit rule on what to do when LinkedIn scraping is blocked | Hard fallback rule: ask for PDF export immediately, do not proceed empty |
| F-13 | File naming convention mentioned once, never enforced | File name rule is part of the final output block (section 11) |
| F-14 | Skill had no version history or upgrade path | Version field added to frontmatter |
| F-15 | GitHub was listed as a source but extraction rules were missing | GitHub extraction rules added (section 4f) |

---

## 1. Invocation

```
Use @cv-generator to build my CV from my LinkedIn PDF.
Use @cv-generator to tailor my CV for this job description.
Use @cv-generator to improve my existing draft.
Use @cv-generator to create a fresh CV via questionnaire.
Use @cv-generator — I want a FlowCV-ready output.
```

Any combination of sources is valid. Multiple sources are merged and deduplicated
before writing begins.

---

## Source Selection

Ask the user which source(s) to use. At least one is required.
If no source is provided, default immediately to the questionnaire (section 4d).

| # | Source | Instruction |
|---|--------|-------------|
| 1 | LinkedIn profile URL | Fetch page; extract all visible sections. **If blocked or empty: immediately ask for a LinkedIn PDF — do not proceed on an empty extraction.** |
| 2 | LinkedIn PDF export | Parse uploaded file. If scanned image: apply OCR and warn the user to verify accuracy. |
| 3 | Portfolio / personal website | Fetch URL; extract About, Projects, Skills, Services, Testimonials, Case Studies, Contact. |
| 4 | Questionnaire | Step-by-step (section 4d). One question at a time. |
| 5 | Existing CV or draft | Upload or paste; improve only — never alter facts. |
| 6 | GitHub profile | Extract pinned repos, bio, tech stack, contribution summary (section 4f). |
| 7 | Resume file (DOCX / PDF / TXT) | Parse and rewrite. Flag scanned PDFs; apply OCR. |

---

## Purpose, seniority, and format

### Purpose

Ask after source selection:

> "What is the main purpose of this CV?"

| Purpose | Key adaptation |
|---------|----------------|
| Applying for a specific job | Full JD analysis + keyword targeting (section 9) |
| General professional CV | Balanced, role-agnostic, reverse-chronological |
| Internship / entry-level | Education and projects lead; transferable skills foregrounded |
| Academic / research | Publications, grants, teaching, research interests |
| Freelance / client proposal | Deliverables, outcomes, services |
| Career change | Functional or hybrid; transferable skills reframed |
| Executive / board-level | Executive summary, board positions, P&L scope |
| Military-to-civilian | Translate ranks and jargon to civilian equivalents |
| Return to work / career break | Frame gap positively; emphasise upskilling |
| Other | Ask the user to describe the 
