---
name: android-dev
description: Production-grade Android app development guide covering native (Kotlin/Java), cross-platform (Flutter, RN, KMM), and hybrid architectures. 
category: Document Processing
source: antigravity
tags: [javascript, typescript, react, api, ai, design, document, presentation, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/android-dev
---


# Android App Development Skill

## Overview

This skill guides production-grade Android and cross-platform (non-iOS) app development following practices used at big tech companies. It covers the entire development lifecycle — architecture, UI, code quality, testing, error handling, release, and maintenance.

## When to Use This Skill

- Use when deciding on a tech stack (see §1 Stack Selection)
- Use when setting up project architecture (see §2 Architecture)
- Use when designing UI, screens, or a design system (see §3 UI & Design)
- Use when ensuring code quality, patterns, or APIs (see Best Practices)
- Use when implementing error handling or debugging crashes (see §5 Error Handling)
- Use when planning testing strategy (see §6 Testing)
- Use when configuring build, CI/CD, or release pipelines (see §7 Build & Release)
- Use when optimizing performance or memory (see §8 Performance)
- Use when debugging or fixing bugs (see §9 Debugging)
- Use when following the full development roadmap (see §10 Development Roadmap)
- Use when needing deep reference for a stack (see `references/` directory)

---

## §1 Stack Selection

Choose based on team, requirements, and platform targets. **Do not recommend iOS-specific paths.**

### Native Android — Kotlin + Jetpack Compose
**Best for:** Android-only apps, hardware-intensive features, best-in-class UX, new projects.
- Language: **Kotlin**
- UI: **Jetpack Compose** (modern declarative UI)
- Key libs: Room, Retrofit/Ktor, Hilt, WorkManager, DataStore, Navigation Compose
- Reference: `references/native-android.md`

### Native Android — Java + XML Views
**Best for:** Existing Java codebases, teams without Kotlin experience, legacy app maintenance, incremental Kotlin migration.
- Language: **Java** (fully supported by Google, not deprecated)
- UI: **XML Layouts** (ConstraintLayout, RecyclerView, ViewBinding)
- Key libs: Room, Retrofit, Hilt, WorkManager, LiveData, ViewModel
- Java and Kotlin **coexist seamlessly** in the same project — migrate incrementally
- Reference: `references/java-android.md`

### Flutter (Dart)
**Best for:** Android + Web (+ desktop) from one codebase, fast iteration, pixel-perfect custom UI.
- Language: **Dart**
- UI: Flutter Widget tree (Material 3 / Cupertino widgets available but target Material for Android)
- Key libs: Provider/Riverpod/Bloc, Dio, Drift/Isar, go_router, flutter_local_notifications
- Reference: `references/flutter.md`

### React Native (JavaScript/TypeScript)
**Best for:** Web + Android code sharing, JS/TS teams, rich ecosystem.
- Language: **TypeScript** (preferred)
- UI: React Native core components + NativeWind / React Native Paper
- Key libs: React Navigation, Zustand/Redux Toolkit, React Query, MMKV
- Reference: `references/react-native.md`

### Kotlin Multiplatform (KMM / Compose Multiplatform)
**Best for:** Sharing business logic across Android + Desktop + Web while keeping native Android UI.
- Language: **Kotlin** everywhere
- UI: Native Compose on Android; Compose Multiplatform for shared UI
- Key libs: Ktor, SQLDelight, Koin, kotlinx.serialization, Napier
- Reference: `references/kmm.md`

### Hybrid (Capacitor / Ionic)
**Best for:** Web-first teams, simple apps, PWA-like content apps.
- Language: TypeScript + HTML/CSS
- UI: Ionic components or custom web UI
- Avoid for: Heavy animations, native sensor access, high-performance games
- Reference: `references/hybrid.md`

### Decision Matrix

| Requirement | Native Kotlin | Native Java | Flutter | RN | KMM | Hybrid |
|---|---|---|---|---|---|---|
| Android-only (new) | ✅ Best | ✅ | ✅ | ✅ | ✅ | ✅ |
| Android-only (existing Java) | ⚠️ migrate | ✅ Best | ❌ | ❌ | ⚠️ | ❌ |
| Android + Web | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ Best |
| Android + Desktop | ❌ | ❌ | ✅ | ⚠️ | ✅ | ⚠️ |
| Shared business logic only | N/A | N/A | N/A | N/A | ✅ Best | N/A |
| Native performance | ✅ | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| JS/TS team | ❌ | ❌ | ❌ | ✅ Best | ❌ | ✅ |
| Custom pixel-perfect UI | ✅ | ⚠️ | ✅ Best | ⚠️ | ✅ | ❌ |

---

## §2 Architecture

### Core Principle: Separation of Concerns
Every production Android project must separate **UI**, **business logic**, and **data** into distinct, independently testable layers.

### Recommended Architecture: Clean Architecture + MVI/MVVM

```
app/
├── ui/              # Composables / Activities / Fragments / Screen states
├── presentation/    # ViewModels, UI State, UI Events
├── domain/          # Use cases, domain models, repository interfaces
├── data/            # Repository impl, remote (API), local (DB), mappers
└── di/              # Dependency injection modules
```

**Data flow (unidirectional):**
```
User Action → ViewModel/Store → Use Case → Repository → Data Source
                    ↓
             UI State (sealed class / StateFlow)
                    ↓
             Composable / View renders state
```

### Key Architecture Patterns by Stack

**Native (MVVM + MVI):**
- `StateFlow` / `SharedFlow` for reactive state
- `sealed class UiState` + `sealed class UiEven
