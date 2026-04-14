---
name: fp-refactor
description: Comprehensive guide for refactoring imperative TypeScript code to fp-ts functional patterns 
category: Document Processing
source: antigravity
tags: [typescript, node, api, ai, document, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-refactor
---


# Refactoring Imperative Code to fp-ts

This skill provides comprehensive patterns and strategies for migrating existing imperative TypeScript code to fp-ts functional programming patterns.

## When to Use
- You are refactoring an existing imperative TypeScript codebase toward fp-ts patterns.
- The task involves converting `try/catch`, null checks, callbacks, DI, or loops into functional equivalents.
- You need migration guidance and tradeoffs, not just isolated fp-ts examples.

## Table of Contents

1. [Converting try-catch to Either/TaskEither](#1-converting-try-catch-to-eithertaskeither)
2. [Converting null checks to Option](#2-converting-null-checks-to-option)
3. [Converting callbacks to Task](#3-converting-callbacks-to-task)
4. [Converting class-based DI to Reader](#4-converting-class-based-di-to-reader)
5. [Converting imperative loops to functional operations](#5-converting-imperative-loops-to-functional-operations)
6. [Migrating Promise chains to TaskEither](#6-migrating-promise-chains-to-taskeither)
7. [Common Pitfalls](#7-common-pitfalls)
8. [Gradual Adoption Strategies](#8-gradual-adoption-strategies)
9. [When NOT to Refactor](#9-when-not-to-refactor)

---

## 1. Converting try-catch to Either/TaskEither

### The Problem with try-catch

Traditional try-catch blocks have several issues:
- Error handling is implicit and easy to forget
- The type system doesn't track which functions can throw
- Control flow is non-linear and harder to reason about
- Composing multiple fallible operations is verbose

### Pattern: Synchronous try-catch to Either

#### Before (Imperative)

```typescript
function parseJSON(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch (error) {
    throw new Error(`Invalid JSON: ${error}`);
  }
}

function validateUser(data: unknown): User {
  try {
    if (!data || typeof data !== 'object') {
      throw new Error('Data must be an object');
    }
    const obj = data as Record<string, unknown>;
    if (typeof obj.name !== 'string') {
      throw new Error('Name is required');
    }
    if (typeof obj.age !== 'number') {
      throw new Error('Age must be a number');
    }
    return { name: obj.name, age: obj.age };
  } catch (error) {
    throw error;
  }
}

// Usage with nested try-catch
function processUserInput(input: string): User | null {
  try {
    const data = parseJSON(input);
    const user = validateUser(data);
    return user;
  } catch (error) {
    console.error('Failed to process user:', error);
    return null;
  }
}
```

#### After (fp-ts Either)

```typescript
import * as E from 'fp-ts/Either';
import * as J from 'fp-ts/Json';
import { pipe } from 'fp-ts/function';

interface User {
  name: string;
  age: number;
}

// Use Json.parse which returns Either<Error, Json>
const parseJSON = (input: string): E.Either<Error, unknown> =>
  pipe(
    J.parse(input),
    E.mapLeft((e) => new Error(`Invalid JSON: ${e}`))
  );

// Validation returns Either, making errors explicit in types
const validateUser = (data: unknown): E.Either<Error, User> => {
  if (!data || typeof data !== 'object') {
    return E.left(new Error('Data must be an object'));
  }
  const obj = data as Record<string, unknown>;
  if (typeof obj.name !== 'string') {
    return E.left(new Error('Name is required'));
  }
  if (typeof obj.age !== 'number') {
    return E.left(new Error('Age must be a number'));
  }
  return E.right({ name: obj.name, age: obj.age });
};

// Compose with pipe and flatMap - errors propagate automatically
const processUserInput = (input: string): E.Either<Error, User> =>
  pipe(
    parseJSON(input),
    E.flatMap(validateUser)
  );

// Handle both cases explicitly
pipe(
  processUserInput('{"name": "Alice", "age": 30}'),
  E.match(
    (error) => console.error('Failed to process user:', error.message),
    (user) => console.log('User:', user)
  )
);
```

### Step-by-Step Refactoring Guide

1. **Identify the error type**: Determine what errors can occur and create appropriate error types
2. **Change return type**: From `T` to `Either<E, T>` where `E` is your error type
3. **Replace throw statements**: Convert `throw new Error(...)` to `E.left(new Error(...))`
4. **Replace return statements**: Convert `return value` to `E.right(value)`
5. **Remove try-catch blocks**: They're no longer needed
6. **Update callers**: Use `pipe` with `E.flatMap` to chain operations

### Pattern: Async try-catch to TaskEither

#### Before (Imperative)

```typescript
async function fetchUser(id: string): Promise<User> {
  try {
    const response = await fetch(`/api/users/${id}`);
    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }
    const data = await response.json();
    return validateUser(data);
  } catch (error) {
    throw new Error(`Failed to fetch user: ${error}`);
  }
}

async function fetchUserPosts(userId: string): Promise<Post[]> {
  try {
    const response = await fetch(`/api/users/${userId}/posts`);
    if (!response.ok) {
    
