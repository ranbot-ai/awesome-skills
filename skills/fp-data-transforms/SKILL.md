---
name: fp-data-transforms
description: Everyday data transformations using functional patterns - arrays, objects, grouping, aggregation, and null-safe access 
category: Development & Code Tools
source: antigravity
tags: [typescript, api, claude, ai, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-data-transforms
---


# Practical Data Transformations

This skill covers the data transformations you do every day: working with arrays, reshaping objects, normalizing API responses, grouping data, and safely accessing nested values. Each section shows the imperative approach first, then the functional equivalent, with honest assessments of when each approach shines.

## When to Use
- You need to transform arrays, objects, grouped data, or nested values in TypeScript.
- The task involves reshaping API responses, null-safe access, aggregation, or normalization.
- You want practical functional patterns for everyday data work instead of low-level loops.

---

## Table of Contents

1. [Array Operations](#1-array-operations)
2. [Object Transformations](#2-object-transformations)
3. [Data Normalization](#3-data-normalization)
4. [Grouping and Aggregation](#4-grouping-and-aggregation)
5. [Null-Safe Access](#5-null-safe-access)
6. [Real-World Examples](#6-real-world-examples)
7. [When to Use What](#7-when-to-use-what)

---

## 1. Array Operations

Array operations are the bread and butter of data transformation. Let's replace verbose loops with expressive, chainable operations.

### Map: Transform Every Element

**The Task**: Convert an array of prices from cents to dollars.

#### Imperative Approach

```typescript
const pricesInCents = [999, 1499, 2999, 4999];

function convertToDollars(prices: number[]): number[] {
  const result: number[] = [];
  for (let i = 0; i < prices.length; i++) {
    result.push(prices[i] / 100);
  }
  return result;
}

const dollars = convertToDollars(pricesInCents);
// [9.99, 14.99, 29.99, 49.99]
```

#### Functional Approach

```typescript
const pricesInCents = [999, 1499, 2999, 4999];

const toDollars = (cents: number): number => cents / 100;

const dollars = pricesInCents.map(toDollars);
// [9.99, 14.99, 29.99, 49.99]
```

**Why functional is better here**: The intent is immediately clear. `map` says "transform each element." The transformation logic (`toDollars`) is named and reusable. No index management, no manual array building.

### Filter: Keep What Matches

**The Task**: Get all active users from a list.

#### Imperative Approach

```typescript
interface User {
  id: string;
  name: string;
  isActive: boolean;
}

function getActiveUsers(users: User[]): User[] {
  const result: User[] = [];
  for (const user of users) {
    if (user.isActive) {
      result.push(user);
    }
  }
  return result;
}
```

#### Functional Approach

```typescript
const isActive = (user: User): boolean => user.isActive;

const activeUsers = users.filter(isActive);

// Or inline for simple predicates
const activeUsers = users.filter(user => user.isActive);
```

**Why functional is better here**: The predicate (`isActive`) is separated from the iteration logic. You can reuse, test, and compose predicates independently.

### Reduce: Accumulate Into Something New

**The Task**: Calculate the total price of items in a cart.

#### Imperative Approach

```typescript
interface CartItem {
  name: string;
  price: number;
  quantity: number;
}

function calculateTotal(items: CartItem[]): number {
  let total = 0;
  for (const item of items) {
    total += item.price * item.quantity;
  }
  return total;
}
```

#### Functional Approach

```typescript
const calculateTotal = (items: CartItem[]): number =>
  items.reduce(
    (total, item) => total + item.price * item.quantity,
    0
  );

// Or break out the line total calculation
const lineTotal = (item: CartItem): number => item.price * item.quantity;

const calculateTotal = (items: CartItem[]): number =>
  items.map(lineTotal).reduce((a, b) => a + b, 0);
```

**Honest assessment**: For simple sums, the imperative loop is actually quite readable. The functional version shines when you need to compose the accumulation with other transformations, or when the reduction logic is complex enough to benefit from being named.

### Chaining: Combine Operations

**The Task**: Get the names of all active premium users, sorted alphabetically.

#### Imperative Approach

```typescript
interface User {
  id: string;
  name: string;
  isActive: boolean;
  tier: 'free' | 'premium';
}

function getActivePremiumNames(users: User[]): string[] {
  const result: string[] = [];
  for (const user of users) {
    if (user.isActive && user.tier === 'premium') {
      result.push(user.name);
    }
  }
  result.sort((a, b) => a.localeCompare(b));
  return result;
}
```

#### Functional Approach

```typescript
const getActivePremiumNames = (users: User[]): string[] =>
  users
    .filter(user => user.isActive)
    .filter(user => user.tier === 'premium')
    .map(user => user.name)
    .sort((a, b) => a.localeCompare(b));

// Or with named predicates for reuse
const isActive = (user: User): boolean => user.isActive;
const isPremium = (user: User): boolean => user.tier === 'premium';
const getName = (user: User): string => user.name;
const alphabetically = (a: string, b: string): number => a.localeCompare(b);
