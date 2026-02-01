---
name: mobile-design
description: Mobile-first design and engineering doctrine for iOS and Android apps. Covers touch interaction, performance, platform conventions, offline behavior, and mobile-specific decision-making. Teaches princ
category: Creative & Media
source: antigravity
tags: [react, api, ai, design, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/mobile-design
---

# Mobile Design System

**(Mobile-First · Touch-First · Platform-Respectful)**

> **Philosophy:** Touch-first. Battery-conscious. Platform-respectful. Offline-capable.
> **Core Law:** Mobile is NOT a small desktop.
> **Operating Rule:** Think constraints first, aesthetics second.

This skill exists to **prevent desktop-thinking, AI-defaults, and unsafe assumptions** when designing or building mobile applications.

---

## 1. Mobile Feasibility & Risk Index (MFRI)

Before designing or implementing **any mobile feature or screen**, assess feasibility.

### MFRI Dimensions (1–5)

| Dimension                  | Question                                                          |
| -------------------------- | ----------------------------------------------------------------- |
| **Platform Clarity**       | Is the target platform (iOS / Android / both) explicitly defined? |
| **Interaction Complexity** | How complex are gestures, flows, or navigation?                   |
| **Performance Risk**       | Does this involve lists, animations, heavy state, or media?       |
| **Offline Dependence**     | Does the feature break or degrade without network?                |
| **Accessibility Risk**     | Does this impact motor, visual, or cognitive accessibility?       |

### Score Formula

```
MFRI = (Platform Clarity + Accessibility Readiness)
       − (Interaction Complexity + Performance Risk + Offline Dependence)
```

**Range:** `-10 → +10`

### Interpretation

| MFRI     | Meaning   | Required Action                       |
| -------- | --------- | ------------------------------------- |
| **6–10** | Safe      | Proceed normally                      |
| **3–5**  | Moderate  | Add performance + UX validation       |
| **0–2**  | Risky     | Simplify interactions or architecture |
| **< 0**  | Dangerous | Redesign before implementation        |

---

## 2. Mandatory Thinking Before Any Work

### ⛔ STOP: Ask Before Assuming (Required)

If **any of the following are not explicitly stated**, you MUST ask before proceeding:

| Aspect     | Question                                   | Why                                      |
| ---------- | ------------------------------------------ | ---------------------------------------- |
| Platform   | iOS, Android, or both?                     | Affects navigation, gestures, typography |
| Framework  | React Native, Flutter, or native?          | Determines performance and patterns      |
| Navigation | Tabs, stack, drawer?                       | Core UX architecture                     |
| Offline    | Must it work offline?                      | Data & sync strategy                     |
| Devices    | Phone only or tablet too?                  | Layout & density rules                   |
| Audience   | Consumer, enterprise, accessibility needs? | Touch & readability                      |

🚫 **Never default to your favorite stack or pattern.**

---

## 3. Mandatory Reference Reading (Enforced)

### Universal (Always Read First)

| File                          | Purpose                            | Status            |
| ----------------------------- | ---------------------------------- | ----------------- |
| **mobile-design-thinking.md** | Anti-memorization, context-forcing | 🔴 REQUIRED FIRST |
| **touch-psychology.md**       | Fitts’ Law, thumb zones, gestures  | 🔴 REQUIRED       |
| **mobile-performance.md**     | 60fps, memory, battery             | 🔴 REQUIRED       |
| **mobile-backend.md**         | Offline sync, push, APIs           | 🔴 REQUIRED       |
| **mobile-testing.md**         | Device & E2E testing               | 🔴 REQUIRED       |
| **mobile-debugging.md**       | Native vs JS debugging             | 🔴 REQUIRED       |

### Platform-Specific (Conditional)

| Platform       | File                |
| -------------- | ------------------- |
| iOS            | platform-ios.md     |
| Android        | platform-android.md |
| Cross-platform | BOTH above          |

> ❌ If you haven’t read the platform file, you are not allowed to design UI.

---

## 4. AI Mobile Anti-Patterns (Hard Bans)

### 🚫 Performance Sins (Non-Negotiable)

| ❌ Never                   | Why                  | ✅ Always                                |
| ------------------------- | -------------------- | --------------------------------------- |
| ScrollView for long lists | Memory explosion     | FlatList / FlashList / ListView.builder |
| Inline renderItem         | Re-renders all rows  | useCallback + memo                      |
| Index as key              | Reorder bugs         | Stable ID                               |
| JS-thread animations      | Jank                 | Native driver / GPU                     |
| console.log in prod       | JS thread block      | Strip logs                              |
| No memoization            | Battery + perf drain | React.memo / const widgets              |

---

### 🚫 Touch & UX Sins

| ❌ Never               | Why                  | ✅ Alway
