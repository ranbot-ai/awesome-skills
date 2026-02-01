---
name: fp-ts-pragmatic
description: A practical, jargon-free guide to fp-ts functional programming - the 80/20 approach that gets results without the academic overhead. Use when writing TypeScript with fp-ts library. 
category: Development & Code Tools
source: antigravity
tags: [typescript, api, ai, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-ts-pragmatic
---


# Pragmatic Functional Programming

**Read this first.** This guide cuts through the academic jargon and shows you what actually matters. No category theory. No abstract nonsense. Just patterns that make your code better.

## When to Use This Skill

- When starting with fp-ts and need practical guidance
- When writing TypeScript code that handles nullable values, errors, or async operations
- When you want cleaner, more maintainable functional code without the academic overhead
- When refactoring imperative code to functional style

## The Golden Rule

> **If functional programming makes your code harder to read, don't use it.**

FP is a tool, not a religion. Use it when it helps. Skip it when it doesn't.

---

## The 80/20 of FP

These five patterns give you most of the benefits. Master these before exploring anything else.

### 1. Pipe: Chain Operations Clearly

Instead of nesting function calls or creating intermediate variables, chain operations in reading order.

```typescript
import { pipe } from 'fp-ts/function'

// Before: Hard to read (inside-out)
const result = format(validate(parse(input)))

// Before: Too many variables
const parsed = parse(input)
const validated = validate(parsed)
const result = format(validated)

// After: Clear, linear flow
const result = pipe(
  input,
  parse,
  validate,
  format
)
```

**When to use pipe:**
- 3+ transformations on the same data
- You find yourself naming throwaway variables
- Logic reads better top-to-bottom

**When to skip pipe:**
- Just 1-2 operations (direct call is fine)
- The operations don't naturally chain

### 2. Option: Handle Missing Values Without null Checks

Stop writing `if (x !== null && x !== undefined)` everywhere.

```typescript
import * as O from 'fp-ts/Option'
import { pipe } from 'fp-ts/function'

// Before: Defensive null checking
function getUserCity(user: User | null): string {
  if (user === null) return 'Unknown'
  if (user.address === null) return 'Unknown'
  if (user.address.city === null) return 'Unknown'
  return user.address.city
}

// After: Chain through potential missing values
const getUserCity = (user: User | null): string =>
  pipe(
    O.fromNullable(user),
    O.flatMap(u => O.fromNullable(u.address)),
    O.flatMap(a => O.fromNullable(a.city)),
    O.getOrElse(() => 'Unknown')
  )
```

**Plain language translation:**
- `O.fromNullable(x)` = "wrap this value, treating null/undefined as 'nothing'"
- `O.flatMap(fn)` = "if we have something, apply this function"
- `O.getOrElse(() => default)` = "unwrap, or use this default if nothing"

### 3. Either: Make Errors Explicit

Stop throwing exceptions for expected failures. Return errors as values.

```typescript
import * as E from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'

// Before: Hidden failure mode
function parseAge(input: string): number {
  const age = parseInt(input, 10)
  if (isNaN(age)) throw new Error('Invalid age')
  if (age < 0) throw new Error('Age cannot be negative')
  return age
}

// After: Errors are visible in the type
function parseAge(input: string): E.Either<string, number> {
  const age = parseInt(input, 10)
  if (isNaN(age)) return E.left('Invalid age')
  if (age < 0) return E.left('Age cannot be negative')
  return E.right(age)
}

// Using it
const result = parseAge(userInput)
if (E.isRight(result)) {
  console.log(`Age is ${result.right}`)
} else {
  console.log(`Error: ${result.left}`)
}
```

**Plain language translation:**
- `E.right(value)` = "success with this value"
- `E.left(error)` = "failure with this error"
- `E.isRight(x)` = "did it succeed?"

### 4. Map: Transform Without Unpacking

Transform values inside containers without extracting them first.

```typescript
import * as O from 'fp-ts/Option'
import * as E from 'fp-ts/Either'
import * as A from 'fp-ts/Array'
import { pipe } from 'fp-ts/function'

// Transform inside Option
const maybeUser: O.Option<User> = O.some({ name: 'Alice', age: 30 })
const maybeName: O.Option<string> = pipe(
  maybeUser,
  O.map(user => user.name)
)

// Transform inside Either
const result: E.Either<Error, number> = E.right(5)
const doubled: E.Either<Error, number> = pipe(
  result,
  E.map(n => n * 2)
)

// Transform arrays (same concept!)
const numbers = [1, 2, 3]
const doubled = pipe(
  numbers,
  A.map(n => n * 2)
)
```

### 5. FlatMap: Chain Operations That Might Fail

When each step might fail, chain them together.

```typescript
import * as E from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'

const parseJSON = (s: string): E.Either<string, unknown> =>
  E.tryCatch(() => JSON.parse(s), () => 'Invalid JSON')

const extractEmail = (data: unknown): E.Either<string, string> => {
  if (typeof data === 'object' && data !== null && 'email' in data) {
    return E.right((data as { email: string }).email)
  }
  return E.left('No email field')
}

const validateEmail = (email: string): E.Either<string, string> =>
  email.includes('@') ? E.right(email) : E.left('Invalid email format')

// Chain a
