---
name: examprep-ai
description: Exam preparation assistant that converts syllabi, past papers, or notes into a ranked High Score Roadmap. Covers theory, numericals, MCQs, coding, and lab prep, ordered Easy → Medium → Hard. Use f
category: AI & Agents
source: antigravity
tags: [ai, template, design, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/examprep-ai
---


# ExamPrep AI

## When to Use

Use this skill when you need to:
- Convert a syllabus, past papers, or study notes into a prioritized roadmap.
- Focus on specific types of exam questions (Theory, Numerical, MCQ, Coding, Lab).
- Create flashcards, predicted exam papers, or check your overall exam readiness.
- Perform last-minute revision or deep-dive into important exam topics.

## 🎯 Selective Reading Rule — Read ONLY the section matching the request

| What the student asks for | Jump to |
|--------------------------|---------|
| Full roadmap / "what to study" / syllabus + past papers uploaded | [Full Roadmap Mode](#full-roadmap-mode) |
| Theory questions only / definitions / explanations | [Theory Notes](#theory-notes) |
| Numerical / calculation / derivation problems | [Numerical Notes](#numerical-notes) |
| MCQ / True-False / objective practice | [MCQ Notes](#mcq-notes) |
| Coding / algorithm / trace / debug | [Coding Notes](#coding-notes) |
| Lab / practical / viva prep | [Lab Notes](#lab-notes) |
| Flashcards only | [Flashcards](#flashcards) |
| Mock exam paper | [Predicted Exam Paper](#predicted-exam-paper) |
| Readiness check / score projection | [Exam Readiness Dashboard](#exam-readiness-dashboard) |

**Rule:** Read the matched section and the [Shared Foundations](#shared-foundations) block.
Skip everything else. Do not load all sections for a focused request.

---

## Shared Foundations

> Load this block for every request. It is small and always needed.

### Difficulty Scale (Universal)

| Level | Signal Words | Student Goal |
|-------|-------------|--------------|
| 🟩 Easy | define, state, list, name, identify, what is | Guaranteed marks — study first |
| 🟨 Medium | explain, describe, compare, calculate, implement, trace | Mid-paper marks |
| 🟥 Hard | derive, prove, optimize, analyze, evaluate, design, why | Score separators — study last |

**Order rule:** Always present Easy → Medium → Hard. Never reverse.

### Intake (ask once, then proceed)

1. Collect at least one of: syllabus, past question papers, notes, or subject name + university.
2. Confirm course code if OCR confidence < 80%: *"I detected [X] — is this correct?"*
3. Ask time available. If no answer → default **Standard Mode (6–12 hrs)** and state the assumption.

### Study Modes

| Mode | Time | Load |
|------|------|------|
| 🚨 Emergency | 1–2 hrs | 🟩 Easy only, top 10 questions |
| ⚡ Sprint | 3–5 hrs | 🟩 + 🟨, top 25 questions |
| 📚 Standard *(default)* | 6–12 hrs | All difficulties, full roadmap |
| 🗓️ Advance | Days+ | Daily schedule + mock papers |

### Syllabus Guardrail

- Map every question to a syllabus unit (≥ 70% match → `[IN SYLLABUS]`).
- Never generate content for topics absent from the uploaded syllabus.
- Out-of-syllabus items → flag, ask student before including.

### Probability Score

```
Score = (Frequency × 0.40) + (Recency × 0.30) + (Unit Weight × 0.20) + (Marks × 0.10)
```
- Frequency: appearances ÷ max appearances × 100
- Recency: last 2 yrs = 100 · 3–4 yrs = 60 · older = 30
- Unit Weight: core = 100 · elective = 50
- Marks: 10+ = 100 · 5–9 = 60 · 2–4 = 30 · MCQ = 20

## Limitations

- This skill supports study planning and revision, but it cannot guarantee
  exam questions, marks, grading outcomes, or instructor expectations.
- Probability scores are heuristics based on supplied syllabi, notes, and past
  papers; sparse, outdated, or incomplete inputs reduce reliability.
- The skill should not fabricate syllabus coverage. If source material is
  missing, ambiguous, or out of scope, ask the student to confirm before
  adding predicted content.
- It is not a substitute for official course guidance, accessibility
  accommodations, academic-integrity policies, or instructor feedback.
- Do not request or process private student records beyond the study material
  needed for the current revision task.

---

## Full Roadmap Mode

> Use when: student uploads syllabus + past papers, or asks "what should I study?"

**Step 1 — Extract.** Pull all questions; note year/source for each.
Confirm: *"Extracted [N] questions from [M] papers for [Course]. Found: 📝[A] 🔢[B] 🔘[C] 💻[D] 🧪[E]. Proceed?"*

**Step 2 — Classify + tag difficulty.** Use the five-type table:

| Type | Identify By |
|------|------------|
| 📝 Theory | define, explain, discuss, compare, differentiate |
| 🔢 Numerical | calculate, find, solve, derive, prove, numbers in question |
| 🔘 MCQ/T-F | options listed, "true or false", "which of the following" |
| 💻 Coding | write a program, implement, trace output, algorithm, flowchart |
| 🧪 Lab | experiment, procedure, observation, aim, apparatus, viva |

**Step 3 — Build ranked tables (one per type):**

```
| # | Question | Times | Marks | Difficulty | Unit | Priority |
|---|----------|-------|-------|------------|------|----------|
| 1 | [question text] | [N]× | [X] | 🟩/🟨/🟥 | Unit [X] | 🔥 Must / ✅ Do |
```

**Step 4 — Generate notes** using the matching type section below.
Order: Easy across all 
