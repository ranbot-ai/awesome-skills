---
name: fp-backend
description: Functional programming patterns for Node.js/Deno backend development using fp-ts, ReaderTaskEither, and functional dependency injection 
category: Development & Code Tools
source: antigravity
tags: [typescript, node, api, ai, template, prisma]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-backend
---


# fp-ts Backend Patterns

Functional programming patterns for building type-safe, testable backend services using fp-ts.

## When to Use
- You are building or refactoring a Node.js or Deno backend with fp-ts.
- The task involves dependency injection, service composition, or typed backend errors with `ReaderTaskEither`.
- You need functional backend architecture patterns rather than isolated utility snippets.

## Core Concepts

### ReaderTaskEither (RTE)

The `ReaderTaskEither<R, E, A>` type is the backbone of functional backend development:
- **R** (Reader): Dependencies/environment (database, config, logger)
- **E** (Either left): Error type
- **A** (Either right): Success value

```typescript
import * as RTE from 'fp-ts/ReaderTaskEither'
import * as TE from 'fp-ts/TaskEither'
import { pipe } from 'fp-ts/function'

// Define your dependencies
type Deps = {
  db: DatabaseClient
  logger: Logger
  config: Config
}

// Define domain errors
type AppError =
  | { _tag: 'NotFound'; resource: string; id: string }
  | { _tag: 'ValidationError'; message: string }
  | { _tag: 'DatabaseError'; cause: unknown }
  | { _tag: 'Unauthorized'; reason: string }

// A service function
const getUser = (id: string): RTE.ReaderTaskEither<Deps, AppError, User> =>
  pipe(
    RTE.ask<Deps>(),
    RTE.flatMap(({ db, logger }) =>
      pipe(
        RTE.fromTaskEither(db.users.findById(id)),
        RTE.mapLeft((e): AppError => ({ _tag: 'DatabaseError', cause: e })),
        RTE.flatMap(user =>
          user
            ? RTE.right(user)
            : RTE.left({ _tag: 'NotFound', resource: 'User', id })
        ),
        RTE.tap(user => RTE.fromIO(() => logger.info(`Found user: ${user.id}`)))
      )
    )
  )
```

## Service Layer Patterns

### Defining Service Modules

Structure services as modules exporting RTE functions:

```typescript
// src/services/user.service.ts
import * as RTE from 'fp-ts/ReaderTaskEither'
import * as TE from 'fp-ts/TaskEither'
import * as A from 'fp-ts/Array'
import { pipe } from 'fp-ts/function'

type UserDeps = {
  db: DatabaseClient
  hasher: PasswordHasher
  mailer: EmailService
}

type UserError =
  | { _tag: 'UserNotFound'; id: string }
  | { _tag: 'EmailExists'; email: string }
  | { _tag: 'InvalidPassword' }

// Create user
export const create = (
  input: CreateUserInput
): RTE.ReaderTaskEither<UserDeps, UserError, User> =>
  pipe(
    RTE.ask<UserDeps>(),
    RTE.flatMap(({ db, hasher }) =>
      pipe(
        // Check email uniqueness
        checkEmailUnique(input.email),
        RTE.flatMap(() =>
          RTE.fromTaskEither(hasher.hash(input.password))
        ),
        RTE.flatMap(hashedPassword =>
          RTE.fromTaskEither(
            db.users.create({
              ...input,
              password: hashedPassword,
            })
          )
        )
      )
    )
  )

// Find by ID
export const findById = (
  id: string
): RTE.ReaderTaskEither<UserDeps, UserError, User> =>
  pipe(
    RTE.ask<UserDeps>(),
    RTE.flatMap(({ db }) =>
      pipe(
        RTE.fromTaskEither(db.users.findUnique({ where: { id } })),
        RTE.flatMap(user =>
          user
            ? RTE.right(user)
            : RTE.left({ _tag: 'UserNotFound' as const, id })
        )
      )
    )
  )

// Find many with pagination
export const findMany = (
  params: PaginationParams
): RTE.ReaderTaskEither<UserDeps, UserError, PaginatedResult<User>> =>
  pipe(
    RTE.ask<UserDeps>(),
    RTE.flatMap(({ db }) =>
      RTE.fromTaskEither(
        pipe(
          TE.Do,
          TE.bind('users', () => db.users.findMany({
            skip: params.offset,
            take: params.limit,
          })),
          TE.bind('total', () => db.users.count()),
          TE.map(({ users, total }) => ({
            data: users,
            total,
            ...params,
          }))
        )
      )
    )
  )

const checkEmailUnique = (
  email: string
): RTE.ReaderTaskEither<UserDeps, UserError, void> =>
  pipe(
    RTE.ask<UserDeps>(),
    RTE.flatMap(({ db }) =>
      pipe(
        RTE.fromTaskEither(db.users.findUnique({ where: { email } })),
        RTE.flatMap(existing =>
          existing
            ? RTE.left({ _tag: 'EmailExists' as const, email })
            : RTE.right(undefined)
        )
      )
    )
  )
```

### Composing Services

```typescript
// src/services/order.service.ts
import * as UserService from './user.service'
import * as ProductService from './product.service'
import * as PaymentService from './payment.service'

type OrderDeps = UserService.UserDeps &
  ProductService.ProductDeps &
  PaymentService.PaymentDeps & {
    db: DatabaseClient
  }

export const createOrder = (
  userId: string,
  items: OrderItem[]
): RTE.ReaderTaskEither<OrderDeps, OrderError, Order> =>
  pipe(
    RTE.Do,
    // Validate user exists
    RTE.bind('user', () =>
      pipe(
        UserService.findById(userId),
        RTE.mapLeft(toOrderError)
      )
    ),
    // Validate and get products
    RTE.bind('products
