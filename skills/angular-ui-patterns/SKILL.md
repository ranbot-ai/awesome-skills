---
name: angular-ui-patterns
description: Modern Angular UI patterns for loading states, error handling, and data display. Use when building UI components, handling async data, or managing component states. 
category: Creative & Media
source: antigravity
tags: [typescript, ai, template, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/angular-ui-patterns
---


# Angular UI Patterns

## Core Principles

1. **Never show stale UI** - Loading states only when actually loading
2. **Always surface errors** - Users must know when something fails
3. **Optimistic updates** - Make the UI feel instant
4. **Progressive disclosure** - Use `@defer` to show content as available
5. **Graceful degradation** - Partial data is better than no data

---

## Loading State Patterns

### The Golden Rule

**Show loading indicator ONLY when there's no data to display.**

```typescript
@Component({
  template: `
    @if (error()) {
      <app-error-state [error]="error()" (retry)="load()" />
    } @else if (loading() && !items().length) {
      <app-skeleton-list />
    } @else if (!items().length) {
      <app-empty-state message="No items found" />
    } @else {
      <app-item-list [items]="items()" />
    }
  `,
})
export class ItemListComponent {
  private store = inject(ItemStore);

  items = this.store.items;
  loading = this.store.loading;
  error = this.store.error;
}
```

### Loading State Decision Tree

```
Is there an error?
  → Yes: Show error state with retry option
  → No: Continue

Is it loading AND we have no data?
  → Yes: Show loading indicator (spinner/skeleton)
  → No: Continue

Do we have data?
  → Yes, with items: Show the data
  → Yes, but empty: Show empty state
  → No: Show loading (fallback)
```

### Skeleton vs Spinner

| Use Skeleton When    | Use Spinner When      |
| -------------------- | --------------------- |
| Known content shape  | Unknown content shape |
| List/card layouts    | Modal actions         |
| Initial page load    | Button submissions    |
| Content placeholders | Inline operations     |

---

## Control Flow Patterns

### @if/@else for Conditional Rendering

```html
@if (user(); as user) {
<span>Welcome, {{ user.name }}</span>
} @else if (loading()) {
<app-spinner size="small" />
} @else {
<a routerLink="/login">Sign In</a>
}
```

### @for with Track

```html
@for (item of items(); track item.id) {
<app-item-card [item]="item" (delete)="remove(item.id)" />
} @empty {
<app-empty-state
  icon="inbox"
  message="No items yet"
  actionLabel="Create Item"
  (action)="create()"
/>
}
```

### @defer for Progressive Loading

```html
<!-- Critical content loads immediately -->
<app-header />
<app-hero-section />

<!-- Non-critical content deferred -->
@defer (on viewport) {
<app-comments [postId]="postId()" />
} @placeholder {
<div class="h-32 bg-gray-100 animate-pulse"></div>
} @loading (minimum 200ms) {
<app-spinner />
} @error {
<app-error-state message="Failed to load comments" />
}
```

---

## Error Handling Patterns

### Error Handling Hierarchy

```
1. Inline error (field-level) → Form validation errors
2. Toast notification → Recoverable errors, user can retry
3. Error banner → Page-level errors, data still partially usable
4. Full error screen → Unrecoverable, needs user action
```

### Always Show Errors

**CRITICAL: Never swallow errors silently.**

```typescript
// CORRECT - Error always surfaced to user
@Component({...})
export class CreateItemComponent {
  private store = inject(ItemStore);
  private toast = inject(ToastService);

  async create(data: CreateItemDto) {
    try {
      await this.store.create(data);
      this.toast.success('Item created successfully');
      this.router.navigate(['/items']);
    } catch (error) {
      console.error('createItem failed:', error);
      this.toast.error('Failed to create item. Please try again.');
    }
  }
}

// WRONG - Error silently caught
async create(data: CreateItemDto) {
  try {
    await this.store.create(data);
  } catch (error) {
    console.error(error); // User sees nothing!
  }
}
```

### Error State Component Pattern

```typescript
@Component({
  selector: "app-error-state",
  standalone: true,
  imports: [NgOptimizedImage],
  template: `
    <div class="error-state">
      <img ngSrc="/assets/error-icon.svg" width="64" height="64" alt="" />
      <h3>{{ title() }}</h3>
      <p>{{ message() }}</p>
      @if (retry.observed) {
        <button (click)="retry.emit()" class="btn-primary">Try Again</button>
      }
    </div>
  `,
})
export class ErrorStateComponent {
  title = input("Something went wrong");
  message = input("An unexpected error occurred");
  retry = output<void>();
}
```

---

## Button State Patterns

### Button Loading State

```html
<button
  (click)="handleSubmit()"
  [disabled]="isSubmitting() || !form.valid"
  class="btn-primary"
>
  @if (isSubmitting()) {
  <app-spinner size="small" class="mr-2" />
  Saving... } @else { Save Changes }
</button>
```

### Disable During Operations

**CRITICAL: Always disable triggers during async operations.**

```typescript
// CORRECT - Button disabled while loading
@Component({
  template: `
    <button
      [disabled]="saving()"
      (click)="save()"
    >
      @if (saving()) {
        <app-spinner size="sm" /> Saving...
      } @else {
        Save
      }
    </button>
  `
})
export class SaveButtonComponent {
 
