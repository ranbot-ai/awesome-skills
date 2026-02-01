---
name: fp-ts-errors
description: Handle errors as values using fp-ts Either and TaskEither for cleaner, more predictable TypeScript code. Use when implementing error handling patterns with fp-ts. 
category: Business & Marketing
source: antigravity
tags: [typescript, api, ai, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-ts-errors
---


# Practical Error Handling with fp-ts

This skill teaches you how to handle errors without try/catch spaghetti. No academic jargon - just practical patterns for real problems.

## When to Use This Skill

- When you want type-safe error handling in TypeScript
- When replacing try/catch with Either and TaskEither patterns
- When building APIs or services that need explicit error types
- When accumulating multiple validation errors

The core idea: **Errors are just data**. Instead of throwing them into the void and hoping someone catches them, return them as values that TypeScript can track.

---

## 1. Stop Throwing Everywhere

### The Problem with Exceptions

Exceptions are invisible in your types. They break the contract between functions.

```typescript
// What this function signature promises:
function getUser(id: string): User

// What it actually does:
function getUser(id: string): User {
  if (!id) throw new Error('ID required')
  const user = db.find(id)
  if (!user) throw new Error('User not found')
  return user
}

// The caller has no idea this can fail
const user = getUser(id) // Might explode!
```

You end up with code like this:

```typescript
// MESSY: try/catch everywhere
function processOrder(orderId: string) {
  let order
  try {
    order = getOrder(orderId)
  } catch (e) {
    console.error('Failed to get order')
    return null
  }

  let user
  try {
    user = getUser(order.userId)
  } catch (e) {
    console.error('Failed to get user')
    return null
  }

  let payment
  try {
    payment = chargeCard(user.cardId, order.total)
  } catch (e) {
    console.error('Payment failed')
    return null
  }

  return { order, user, payment }
}
```

### The Solution: Return Errors as Values

```typescript
import * as E from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'

// Now TypeScript KNOWS this can fail
function getUser(id: string): E.Either<string, User> {
  if (!id) return E.left('ID required')
  const user = db.find(id)
  if (!user) return E.left('User not found')
  return E.right(user)
}

// The caller is forced to handle both cases
const result = getUser(id)
// result is Either<string, User> - error OR success, never both
```

---

## 2. The Result Pattern (Either)

`Either<E, A>` is simple: it holds either an error (`E`) or a value (`A`).

- `Left` = error case
- `Right` = success case (think "right" as in "correct")

```typescript
import * as E from 'fp-ts/Either'

// Creating values
const success = E.right(42)           // Right(42)
const failure = E.left('Oops')        // Left('Oops')

// Checking what you have
if (E.isRight(result)) {
  console.log(result.right) // The success value
} else {
  console.log(result.left)  // The error
}

// Better: pattern match with fold
const message = pipe(
  result,
  E.fold(
    (error) => `Failed: ${error}`,
    (value) => `Got: ${value}`
  )
)
```

### Converting Throwing Code to Either

```typescript
// Wrap any throwing function with tryCatch
const parseJSON = (json: string): E.Either<Error, unknown> =>
  E.tryCatch(
    () => JSON.parse(json),
    (e) => (e instanceof Error ? e : new Error(String(e)))
  )

parseJSON('{"valid": true}')  // Right({ valid: true })
parseJSON('not json')          // Left(SyntaxError: ...)

// For functions you'll reuse, use tryCatchK
const safeParseJSON = E.tryCatchK(
  JSON.parse,
  (e) => (e instanceof Error ? e : new Error(String(e)))
)
```

### Common Either Operations

```typescript
import * as E from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'

// Transform the success value
const doubled = pipe(
  E.right(21),
  E.map(n => n * 2)
) // Right(42)

// Transform the error
const betterError = pipe(
  E.left('bad'),
  E.mapLeft(e => `Error: ${e}`)
) // Left('Error: bad')

// Provide a default for errors
const value = pipe(
  E.left('failed'),
  E.getOrElse(() => 0)
) // 0

// Convert nullable to Either
const fromNullable = E.fromNullable('not found')
fromNullable(user)  // Right(user) if exists, Left('not found') if null/undefined
```

---

## 3. Chaining Operations That Might Fail

The real power comes from chaining. Each step can fail, but you write it as a clean pipeline.

### Before: Nested Try/Catch Hell

```typescript
// MESSY: Each step can fail, nested try/catch everywhere
function processUserOrder(userId: string, productId: string): Result | null {
  let user
  try {
    user = getUser(userId)
  } catch (e) {
    logError('User fetch failed', e)
    return null
  }

  if (!user.isActive) {
    logError('User not active')
    return null
  }

  let product
  try {
    product = getProduct(productId)
  } catch (e) {
    logError('Product fetch failed', e)
    return null
  }

  if (product.stock < 1) {
    logError('Out of stock')
    return null
  }

  let order
  try {
    order = createOrder(user, product)
  } catch (e) {
    logError('Order creation failed', e)
    return null
  }

  return order
}
```

### After: Clean Chain with Either

```typescript
import * as E from 'fp-ts/Either
