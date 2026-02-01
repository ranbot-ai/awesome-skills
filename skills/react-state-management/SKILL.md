---
name: react-state-management
description: Master modern React state management with Redux Toolkit, Zustand, Jotai, and React Query. Use when setting up global state, managing server state, or choosing between state management solutions. 
category: Document Processing
source: antigravity
tags: [typescript, react, api, ai, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/react-state-management
---


# React State Management

Comprehensive guide to modern React state management patterns, from local component state to global stores and server state synchronization.

## Do not use this skill when

- The task is unrelated to react state management
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Setting up global state management in a React app
- Choosing between Redux Toolkit, Zustand, or Jotai
- Managing server state with React Query or SWR
- Implementing optimistic updates
- Debugging state-related issues
- Migrating from legacy Redux to modern patterns

## Core Concepts

### 1. State Categories

| Type | Description | Solutions |
|------|-------------|-----------|
| **Local State** | Component-specific, UI state | useState, useReducer |
| **Global State** | Shared across components | Redux Toolkit, Zustand, Jotai |
| **Server State** | Remote data, caching | React Query, SWR, RTK Query |
| **URL State** | Route parameters, search | React Router, nuqs |
| **Form State** | Input values, validation | React Hook Form, Formik |

### 2. Selection Criteria

```
Small app, simple state → Zustand or Jotai
Large app, complex state → Redux Toolkit
Heavy server interaction → React Query + light client state
Atomic/granular updates → Jotai
```

## Quick Start

### Zustand (Simplest)

```typescript
// store/useStore.ts
import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

interface AppState {
  user: User | null
  theme: 'light' | 'dark'
  setUser: (user: User | null) => void
  toggleTheme: () => void
}

export const useStore = create<AppState>()(
  devtools(
    persist(
      (set) => ({
        user: null,
        theme: 'light',
        setUser: (user) => set({ user }),
        toggleTheme: () => set((state) => ({
          theme: state.theme === 'light' ? 'dark' : 'light'
        })),
      }),
      { name: 'app-storage' }
    )
  )
)

// Usage in component
function Header() {
  const { user, theme, toggleTheme } = useStore()
  return (
    <header className={theme}>
      {user?.name}
      <button onClick={toggleTheme}>Toggle Theme</button>
    </header>
  )
}
```

## Patterns

### Pattern 1: Redux Toolkit with TypeScript

```typescript
// store/index.ts
import { configureStore } from '@reduxjs/toolkit'
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux'
import userReducer from './slices/userSlice'
import cartReducer from './slices/cartSlice'

export const store = configureStore({
  reducer: {
    user: userReducer,
    cart: cartReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch

// Typed hooks
export const useAppDispatch: () => AppDispatch = useDispatch
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector
```

```typescript
// store/slices/userSlice.ts
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'

interface User {
  id: string
  email: string
  name: string
}

interface UserState {
  current: User | null
  status: 'idle' | 'loading' | 'succeeded' | 'failed'
  error: string | null
}

const initialState: UserState = {
  current: null,
  status: 'idle',
  error: null,
}

export const fetchUser = createAsyncThunk(
  'user/fetchUser',
  async (userId: string, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/users/${userId}`)
      if (!response.ok) throw new Error('Failed to fetch user')
      return await response.json()
    } catch (error) {
      return rejectWithValue((error as Error).message)
    }
  }
)

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setUser: (state, action: PayloadAction<User>) => {
      state.current = action.payload
      state.status = 'succeeded'
    },
    clearUser: (state) => {
      state.current = null
      state.status = 'idle'
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchUser.pending, (state) => {
        state.status = 'loading'
        state.error = null
      })
      .addCase(fetchUser.fulfilled, (state, action) => {
        state.status = 'succeeded'
        state.current = action.payload
      })
      .addCase(fetchUser.rejected, (state, action) => {
        state.status = 'failed'
        state.error = action.payload as string
      })
  },
})

export const { setUser, clearUser } = userSlice.actions
export default userSlice.reducer
```

### Pattern 2: Zustand with Slices (Scalable)

```typescript
// store/slices/createUserSlice.ts
import { StateCreator }
