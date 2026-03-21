---
name: native-data-fetching
description: Use when implementing or debugging ANY network request, API call, or data fetching. Covers fetch API, React Query, SWR, error handling, caching, offline support, and Expo Router data loaders (useLoade
category: AI & Agents
source: antigravity
tags: [javascript, typescript, react, node, api, ai, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/native-data-fetching
---


# Expo Networking

**You MUST use this skill for ANY networking work including API requests, data fetching, caching, or network debugging.**

## References

Consult these resources as needed:

```
references/
  expo-router-loaders.md   Route-level data loading with Expo Router loaders (web, SDK 55+)
```

## When to Use
Use this skill when:

- Implementing API requests
- Setting up data fetching (React Query, SWR)
- Using Expo Router data loaders (`useLoaderData`, web SDK 55+)
- Debugging network failures
- Implementing caching strategies
- Handling offline scenarios
- Authentication/token management
- Configuring API URLs and environment variables

## Preferences

- Avoid axios, prefer expo/fetch

## Common Issues & Solutions

### 1. Basic Fetch Usage

**Simple GET request**:

```tsx
const fetchUser = async (userId: string) => {
  const response = await fetch(`https://api.example.com/users/${userId}`);

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
};
```

**POST request with body**:

```tsx
const createUser = async (userData: UserData) => {
  const response = await fetch("https://api.example.com/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(userData),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message);
  }

  return response.json();
};
```

---

### 2. React Query (TanStack Query)

**Setup**:

```tsx
// app/_layout.tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 2,
    },
  },
});

export default function RootLayout() {
  return (
    <QueryClientProvider client={queryClient}>
      <Stack />
    </QueryClientProvider>
  );
}
```

**Fetching data**:

```tsx
import { useQuery } from "@tanstack/react-query";

function UserProfile({ userId }: { userId: string }) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["user", userId],
    queryFn: () => fetchUser(userId),
  });

  if (isLoading) return <Loading />;
  if (error) return <Error message={error.message} />;

  return <Profile user={data} />;
}
```

**Mutations**:

```tsx
import { useMutation, useQueryClient } from "@tanstack/react-query";

function CreateUserForm() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      // Invalidate and refetch
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const handleSubmit = (data: UserData) => {
    mutation.mutate(data);
  };

  return <Form onSubmit={handleSubmit} isLoading={mutation.isPending} />;
}
```

---

### 3. Error Handling

**Comprehensive error handling**:

```tsx
class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string) {
    super(message);
    this.name = "ApiError";
  }
}

const fetchWithErrorHandling = async (url: string, options?: RequestInit) => {
  try {
    const response = await fetch(url, options);

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new ApiError(
        error.message || "Request failed",
        response.status,
        error.code
      );
    }

    return response.json();
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    // Network error (no internet, timeout, etc.)
    throw new ApiError("Network error", 0, "NETWORK_ERROR");
  }
};
```

**Retry logic**:

```tsx
const fetchWithRetry = async (
  url: string,
  options?: RequestInit,
  retries = 3
) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await fetchWithErrorHandling(url, options);
    } catch (error) {
      if (i === retries - 1) throw error;
      // Exponential backoff
      await new Promise((r) => setTimeout(r, Math.pow(2, i) * 1000));
    }
  }
};
```

---

### 4. Authentication

**Token management**:

```tsx
import * as SecureStore from "expo-secure-store";

const TOKEN_KEY = "auth_token";

export const auth = {
  getToken: () => SecureStore.getItemAsync(TOKEN_KEY),
  setToken: (token: string) => SecureStore.setItemAsync(TOKEN_KEY, token),
  removeToken: () => SecureStore.deleteItemAsync(TOKEN_KEY),
};

// Authenticated fetch wrapper
const authFetch = async (url: string, options: RequestInit = {}) => {
  const token = await auth.getToken();

  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: token ? `Bearer ${token}` : "",
    },
  });
};
```

**Token refresh**:

```tsx
let isRefreshing = false;
let refreshPromise: Promise<string> | null = null;

const getValidToken = async (): Promise<string> => {
  const token = await auth.getToken();

  if (!token || isTokenExpired(token)) {
    if (!isRefre
