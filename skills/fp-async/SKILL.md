---
name: fp-async
description: Practical async patterns using TaskEither - clean pipelines instead of try/catch hell, with real API examples 
category: AI & Agents
source: antigravity
tags: [typescript, node, api, ai, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-async
---


# Practical Async Patterns with fp-ts

Stop writing nested try/catch blocks. Stop losing error context. Start building clean async pipelines that handle errors properly.

**TaskEither is simply an async operation that tracks success or failure.** That's it. No fancy terminology needed.

## When to Use
- You need async error handling in TypeScript with `TaskEither`.
- The task involves wrapping Promises, composing API calls, or replacing nested `try/catch` flows.
- You want practical fp-ts async patterns instead of academic explanations.

```typescript
// TaskEither<Error, User> means:
// "An async operation that either fails with Error or succeeds with User"
```

---

## 1. Wrapping Promises Safely

### The Problem: Try/Catch Everywhere

```typescript
// BEFORE: Try/catch hell
async function getUserData(userId: string) {
  try {
    const response = await fetch(`/api/users/${userId}`)
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
    const user = await response.json()

    try {
      const posts = await fetch(`/api/users/${userId}/posts`)
      if (!posts.ok) {
        throw new Error(`HTTP ${posts.status}`)
      }
      const postsData = await posts.json()
      return { user, posts: postsData }
    } catch (postsError) {
      // Now what? Return partial data? Rethrow? Log?
      console.error('Failed to fetch posts:', postsError)
      return { user, posts: [] }
    }
  } catch (error) {
    // Lost all context about what failed
    console.error('Something failed:', error)
    throw error
  }
}
```

### The Solution: Wrap Once, Handle Cleanly

```typescript
import * as TE from 'fp-ts/TaskEither'
import * as E from 'fp-ts/Either'
import { pipe } from 'fp-ts/function'

// One wrapper function - reuse everywhere
const fetchJson = <T>(url: string): TE.TaskEither<Error, T> =>
  TE.tryCatch(
    async () => {
      const response = await fetch(url)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }
      return response.json()
    },
    (error) => error instanceof Error ? error : new Error(String(error))
  )

// AFTER: Clean and composable
const getUser = (userId: string) => fetchJson<User>(`/api/users/${userId}`)
const getPosts = (userId: string) => fetchJson<Post[]>(`/api/users/${userId}/posts`)
```

### tryCatch Explained

`TE.tryCatch` takes two things:
1. An async function that might throw
2. A function to convert the thrown value into your error type

```typescript
TE.tryCatch(
  () => somePromise,           // The async work
  (thrown) => toError(thrown)  // Convert failures to your error type
)
```

### Creating Success and Failure Values

```typescript
// Wrap a value as success
const success = TE.right<Error, number>(42)

// Wrap a value as failure
const failure = TE.left<Error, number>(new Error('Nope'))

// From a nullable value (null/undefined becomes error)
const fromNullable = TE.fromNullable(new Error('Value was null'))
const result = fromNullable(maybeUser) // TaskEither<Error, User>

// From a condition
const mustBePositive = TE.fromPredicate(
  (n: number) => n > 0,
  (n) => new Error(`Expected positive, got ${n}`)
)
```

---

## 2. Chaining Async Operations

### The Problem: Callback Hell / Nested Awaits

```typescript
// BEFORE: Deeply nested, hard to follow
async function processOrder(orderId: string) {
  try {
    const order = await fetchOrder(orderId)
    if (!order) throw new Error('Order not found')

    try {
      const user = await fetchUser(order.userId)
      if (!user) throw new Error('User not found')

      try {
        const inventory = await checkInventory(order.items)
        if (!inventory.available) throw new Error('Out of stock')

        try {
          const payment = await chargePayment(user, order.total)
          if (!payment.success) throw new Error('Payment failed')

          try {
            const shipment = await createShipment(order, user)
            return { order, shipment, payment }
          } catch (e) {
            // Refund payment? Log? What's the state now?
            await refundPayment(payment.id)
            throw e
          }
        } catch (e) {
          throw e
        }
      } catch (e) {
        throw e
      }
    } catch (e) {
      throw e
    }
  } catch (e) {
    console.error('Order processing failed', e)
    throw e
  }
}
```

### The Solution: Clean Pipelines with chain

```typescript
// AFTER: Flat, readable pipeline
const processOrder = (orderId: string) =>
  pipe(
    fetchOrder(orderId),
    TE.chain(order => fetchUser(order.userId)),
    TE.chain(user =>
      pipe(
        checkInventory(order.items),
        TE.chain(inventory => chargePayment(user, order.total))
      )
    ),
    TE.chain(payment => createShipment(order, user, payment))
  )
```

### chain vs map

Use `map` when your transformation is synchronous and can't fail:

```typescript
pipe(
  fetchUser(userId),
  TE.map(user => user.name.toUpperCase())  // Just tran
