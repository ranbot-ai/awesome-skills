---
name: radix-ui-design-system
description: Build accessible design systems with Radix UI primitives. Headless component customization, theming strategies, and compound component patterns for production-grade UI libraries. 
category: Document Processing
source: antigravity
tags: [typescript, react, node, ai, design, document, tailwind]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/radix-ui-design-system
---


# Radix UI Design System

Build production-ready, accessible design systems using Radix UI primitives with full customization control and zero style opinions.

## Overview

Radix UI provides unstyled, accessible components (primitives) that you can customize to match any design system. This skill guides you through building scalable component libraries with Radix UI, focusing on accessibility-first design, theming architecture, and composable patterns.

**Key Strengths:**
- **Headless by design**: Full styling control without fighting defaults
- **Accessibility built-in**: WAI-ARIA compliant, keyboard navigation, screen reader support
- **Composable primitives**: Build complex components from simple building blocks
- **Framework agnostic**: Works with React, but styles work anywhere

## When to Use This Skill

- Creating a custom design system from scratch
- Building accessible UI component libraries
- Implementing complex interactive components (Dialog, Dropdown, Tabs, etc.)
- Migrating from styled component libraries to unstyled primitives
- Setting up theming systems with CSS variables or Tailwind
- Need full control over component behavior and styling
- Building applications requiring WCAG 2.1 AA/AAA compliance

## Do not use this skill when

- You need pre-styled components out of the box (use shadcn/ui, Mantine, etc.)
- Building simple static pages without interactivity
- The project doesn't use React 16.8+ (Radix requires hooks)
- You need components for frameworks other than React

---

## Core Principles

### 1. Accessibility First

Every Radix primitive is built with accessibility as the foundation:

- **Keyboard Navigation**: Full keyboard support (Tab, Arrow keys, Enter, Escape)
- **Screen Readers**: Proper ARIA attributes and live regions
- **Focus Management**: Automatic focus trapping and restoration
- **Disabled States**: Proper handling of disabled and aria-disabled

**Rule**: Never override accessibility features. Enhance, don't replace.

### 2. Headless Architecture

Radix provides **behavior**, you provide **appearance**:

```tsx
// ❌ Don't fight pre-styled components
<Button className="override-everything" />

// ✅ Radix gives you behavior, you add styling
<Dialog.Root>
  <Dialog.Trigger className="your-button-styles" />
  <Dialog.Content className="your-modal-styles" />
</Dialog.Root>
```

### 3. Composition Over Configuration

Build complex components from simple primitives:

```tsx
// Primitive components compose naturally
<Tabs.Root>
  <Tabs.List>
    <Tabs.Trigger value="tab1">Tab 1</Tabs.Trigger>
    <Tabs.Trigger value="tab2">Tab 2</Tabs.Trigger>
  </Tabs.List>
  <Tabs.Content value="tab1">Content 1</Tabs.Content>
  <Tabs.Content value="tab2">Content 2</Tabs.Content>
</Tabs.Root>
```

---

## Getting Started

### Installation

```bash
# Install individual primitives (recommended)
npm install @radix-ui/react-dialog @radix-ui/react-dropdown-menu

# Or install multiple at once
npm install @radix-ui/react-{dialog,dropdown-menu,tabs,tooltip}

# For styling (optional but common)
npm install clsx tailwind-merge class-variance-authority
```

### Basic Component Pattern

Every Radix component follows this pattern:

```tsx
import * as Dialog from '@radix-ui/react-dialog';

export function MyDialog() {
  return (
    <Dialog.Root>
      {/* Trigger the dialog */}
      <Dialog.Trigger asChild>
        <button className="trigger-styles">Open</button>
      </Dialog.Trigger>

      {/* Portal renders outside DOM hierarchy */}
      <Dialog.Portal>
        {/* Overlay (backdrop) */}
        <Dialog.Overlay className="overlay-styles" />
        
        {/* Content (modal) */}
        <Dialog.Content className="content-styles">
          <Dialog.Title>Title</Dialog.Title>
          <Dialog.Description>Description</Dialog.Description>
          
          {/* Your content here */}
          
          <Dialog.Close asChild>
            <button>Close</button>
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
```

---

## Theming Strategies

### Strategy 1: CSS Variables (Framework-Agnostic)

**Best for**: Maximum portability, SSR-friendly

```css
/* globals.css */
:root {
  --color-primary: 220 90% 56%;
  --color-surface: 0 0% 100%;
  --radius-base: 0.5rem;
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
}

[data-theme="dark"] {
  --color-primary: 220 90% 66%;
  --color-surface: 222 47% 11%;
}
```

```tsx
// Component.tsx
<Dialog.Content 
  className="
    bg-[hsl(var(--color-surface))]
    rounded-[var(--radius-base)]
    shadow-[var(--shadow-lg)]
  "
/>
```

### Strategy 2: Tailwind + CVA (Class Variance Authority)

**Best for**: Tailwind projects, variant-heavy components

```tsx
// button.tsx
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  // Base styles
  "inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outlin
