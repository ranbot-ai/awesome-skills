---
name: angular-state-management
description: Master modern Angular state management with Signals, NgRx, and RxJS. Use when setting up global state, managing component stores, choosing between state solutions, or migrating from legacy patterns. 
category: Document Processing
source: antigravity
tags: [typescript, react, api, ai, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/angular-state-management
---


# Angular State Management

Comprehensive guide to modern Angular state management patterns, from Signal-based local state to global stores and server state synchronization.

## When to Use This Skill

- Setting up global state management in Angular
- Choosing between Signals, NgRx, or Akita
- Managing component-level stores
- Implementing optimistic updates
- Debugging state-related issues
- Migrating from legacy state patterns

## Do Not Use This Skill When

- The task is unrelated to Angular state management
- You need React state management → use `react-state-management`

---

## Core Concepts

### State Categories

| Type             | Description                  | Solutions             |
| ---------------- | ---------------------------- | --------------------- |
| **Local State**  | Component-specific, UI state | Signals, `signal()`   |
| **Shared State** | Between related components   | Signal services       |
| **Global State** | App-wide, complex            | NgRx, Akita, Elf      |
| **Server State** | Remote data, caching         | NgRx Query, RxAngular |
| **URL State**    | Route parameters             | ActivatedRoute        |
| **Form State**   | Input values, validation     | Reactive Forms        |

### Selection Criteria

```
Small app, simple state → Signal Services
Medium app, moderate state → Component Stores
Large app, complex state → NgRx Store
Heavy server interaction → NgRx Query + Signal Services
Real-time updates → RxAngular + Signals
```

---

## Quick Start: Signal-Based State

### Pattern 1: Simple Signal Service

```typescript
// services/counter.service.ts
import { Injectable, signal, computed } from "@angular/core";

@Injectable({ providedIn: "root" })
export class CounterService {
  // Private writable signals
  private _count = signal(0);

  // Public read-only
  readonly count = this._count.asReadonly();
  readonly doubled = computed(() => this._count() * 2);
  readonly isPositive = computed(() => this._count() > 0);

  increment() {
    this._count.update((v) => v + 1);
  }

  decrement() {
    this._count.update((v) => v - 1);
  }

  reset() {
    this._count.set(0);
  }
}

// Usage in component
@Component({
  template: `
    <p>Count: {{ counter.count() }}</p>
    <p>Doubled: {{ counter.doubled() }}</p>
    <button (click)="counter.increment()">+</button>
  `,
})
export class CounterComponent {
  counter = inject(CounterService);
}
```

### Pattern 2: Feature Signal Store

```typescript
// stores/user.store.ts
import { Injectable, signal, computed, inject } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { toSignal } from "@angular/core/rxjs-interop";

interface User {
  id: string;
  name: string;
  email: string;
}

interface UserState {
  user: User | null;
  loading: boolean;
  error: string | null;
}

@Injectable({ providedIn: "root" })
export class UserStore {
  private http = inject(HttpClient);

  // State signals
  private _user = signal<User | null>(null);
  private _loading = signal(false);
  private _error = signal<string | null>(null);

  // Selectors (read-only computed)
  readonly user = computed(() => this._user());
  readonly loading = computed(() => this._loading());
  readonly error = computed(() => this._error());
  readonly isAuthenticated = computed(() => this._user() !== null);
  readonly displayName = computed(() => this._user()?.name ?? "Guest");

  // Actions
  async loadUser(id: string) {
    this._loading.set(true);
    this._error.set(null);

    try {
      const user = await fetch(`/api/users/${id}`).then((r) => r.json());
      this._user.set(user);
    } catch (e) {
      this._error.set("Failed to load user");
    } finally {
      this._loading.set(false);
    }
  }

  updateUser(updates: Partial<User>) {
    this._user.update((user) => (user ? { ...user, ...updates } : null));
  }

  logout() {
    this._user.set(null);
    this._error.set(null);
  }
}
```

### Pattern 3: SignalStore (NgRx Signals)

```typescript
// stores/products.store.ts
import {
  signalStore,
  withState,
  withMethods,
  withComputed,
  patchState,
} from "@ngrx/signals";
import { inject } from "@angular/core";
import { ProductService } from "./product.service";

interface ProductState {
  products: Product[];
  loading: boolean;
  filter: string;
}

const initialState: ProductState = {
  products: [],
  loading: false,
  filter: "",
};

export const ProductStore = signalStore(
  { providedIn: "root" },

  withState(initialState),

  withComputed((store) => ({
    filteredProducts: computed(() => {
      const filter = store.filter().toLowerCase();
      return store
        .products()
        .filter((p) => p.name.toLowerCase().includes(filter));
    }),
    totalCount: computed(() => store.products().length),
  })),

  withMethods((store, productService = inject(ProductService)) => ({
    async loadProducts() {
      patchState(store, { loading: true });

      try {
        const products = await productService.getAll();
  
