---
name: fp-ts-react
description: Practical patterns for using fp-ts with React - hooks, state, forms, data fetching. Use when building React apps with functional programming patterns. Works with React 18/19, Next.js 14/15. 
category: Development & Code Tools
source: antigravity
tags: [typescript, react, node, api, ai, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fp-ts-react
---


# Functional Programming in React

Practical patterns for React apps. No jargon, just code that works.

## When to Use This Skill

- When building React apps with fp-ts for type-safe state management
- When handling loading/error/success states in data fetching
- When implementing form validation with error accumulation
- When using React 18/19 or Next.js 14/15 with functional patterns

---

## Quick Reference

| Pattern | Use When |
|---------|----------|
| `Option` | Value might be missing (user not loaded yet) |
| `Either` | Operation might fail (form validation) |
| `TaskEither` | Async operation might fail (API calls) |
| `RemoteData` | Need to show loading/error/success states |
| `pipe` | Chaining multiple transformations |

---

## 1. State with Option (Maybe It's There, Maybe Not)

Use `Option` instead of `null | undefined` for clearer intent.

### Basic Pattern

```typescript
import { useState } from 'react'
import * as O from 'fp-ts/Option'
import { pipe } from 'fp-ts/function'

interface User {
  id: string
  name: string
  email: string
}

function UserProfile() {
  // Option says "this might not exist yet"
  const [user, setUser] = useState<O.Option<User>>(O.none)

  const handleLogin = (userData: User) => {
    setUser(O.some(userData))
  }

  const handleLogout = () => {
    setUser(O.none)
  }

  return pipe(
    user,
    O.match(
      // When there's no user
      () => <button onClick={() => handleLogin({ id: '1', name: 'Alice', email: 'alice@example.com' })}>
        Log In
      </button>,
      // When there's a user
      (u) => (
        <div>
          <p>Welcome, {u.name}!</p>
          <button onClick={handleLogout}>Log Out</button>
        </div>
      )
    )
  )
}
```

### Chaining Optional Values

```typescript
import * as O from 'fp-ts/Option'
import { pipe } from 'fp-ts/function'

interface Profile {
  user: O.Option<{
    name: string
    settings: O.Option<{
      theme: string
    }>
  }>
}

function getTheme(profile: Profile): string {
  return pipe(
    profile.user,
    O.flatMap(u => u.settings),
    O.map(s => s.theme),
    O.getOrElse(() => 'light') // default
  )
}
```

---

## 2. Form Validation with Either

Either is perfect for validation: `Left` = errors, `Right` = valid data.

### Simple Form Validation

```typescript
import * as E from 'fp-ts/Either'
import * as A from 'fp-ts/Array'
import { pipe } from 'fp-ts/function'

// Validation functions return Either<ErrorMessage, ValidValue>
const validateEmail = (email: string): E.Either<string, string> =>
  email.includes('@')
    ? E.right(email)
    : E.left('Invalid email address')

const validatePassword = (password: string): E.Either<string, string> =>
  password.length >= 8
    ? E.right(password)
    : E.left('Password must be at least 8 characters')

const validateName = (name: string): E.Either<string, string> =>
  name.trim().length > 0
    ? E.right(name.trim())
    : E.left('Name is required')
```

### Collecting All Errors (Not Just First One)

```typescript
import * as E from 'fp-ts/Either'
import { sequenceS } from 'fp-ts/Apply'
import { getSemigroup } from 'fp-ts/NonEmptyArray'
import { pipe } from 'fp-ts/function'

// This collects ALL errors, not just the first one
const validateAll = sequenceS(E.getApplicativeValidation(getSemigroup<string>()))

interface SignupForm {
  name: string
  email: string
  password: string
}

interface ValidatedForm {
  name: string
  email: string
  password: string
}

function validateForm(form: SignupForm): E.Either<string[], ValidatedForm> {
  return pipe(
    validateAll({
      name: pipe(validateName(form.name), E.mapLeft(e => [e])),
      email: pipe(validateEmail(form.email), E.mapLeft(e => [e])),
      password: pipe(validatePassword(form.password), E.mapLeft(e => [e])),
    })
  )
}

// Usage in component
function SignupForm() {
  const [form, setForm] = useState({ name: '', email: '', password: '' })
  const [errors, setErrors] = useState<string[]>([])

  const handleSubmit = () => {
    pipe(
      validateForm(form),
      E.match(
        (errs) => setErrors(errs),     // Show all errors
        (valid) => {
          setErrors([])
          submitToServer(valid)         // Submit valid data
        }
      )
    )
  }

  return (
    <form onSubmit={e => { e.preventDefault(); handleSubmit() }}>
      <input
        value={form.name}
        onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
        placeholder="Name"
      />
      <input
        value={form.email}
        onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
        placeholder="Email"
      />
      <input
        type="password"
        value={form.password}
        onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
        placeholder="Password"
      />

      {errors.length > 0 && (
        <ul style={{ color: 'red' }}>
          {errors.map((err, i) => <li key={i}>{err}</li>)}
        </ul>
      )}

      <button type="submit">Sign Up</bu
