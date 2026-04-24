---
name: frontend-api-integration-patterns
description: Production-ready patterns for integrating frontend applications with backend APIs, including race condition handling, request cancellation, retry strategies, error normalization, and UI state manageme
category: Development & Code Tools
source: antigravity
tags: [javascript, react, api, claude, ai, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-api-integration-patterns
---


# Frontend API Integration Patterns

## Overview

This skill provides production-ready patterns for integrating frontend applications with backend APIs.

Most frontend issues are not caused by APIs being difficult to call, but by **incorrect handling of asynchronous behavior**—leading to race conditions, stale data, duplicated requests, and poor user experience.

This skill focuses on **correctness, resilience, and user experience**, not just making API calls work.

---

## When to Use This Skill

* Connecting frontend apps (React, React Native, Vue, etc.) to backend APIs
* Integrating ML/AI endpoints (`/predict`, `/recommend`)
* Handling asynchronous data in UI
* Fixing stale data, flickering UI, or duplicate requests
* Designing scalable frontend API layers

---

## Core Patterns

### 1. API Layer (Separation of Concerns)

Centralize API logic and normalize errors.

```js id="k1m7r2"
export class ApiError extends Error {
  constructor(message, status, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export const apiClient = async (url, options = {}) => {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok) {
    let payload = null;
    try {
      payload = await res.json();
    } catch (_) {}

    throw new ApiError(
      payload?.message || "Request failed",
      res.status,
      payload
    );
  }

  // handle empty responses safely (e.g. 204 No Content)
  if (res.status === 204) return null;

  const text = await res.text();
  return text ? JSON.parse(text) : null;
};
```

---

### 2. Race-Safe State Management

Prevent stale responses from overwriting fresh data.

```js id="y7p4ha"
useEffect(() => {
  let cancelled = false;

  const load = async () => {
    try {
      setLoading(true);
      setError(null);

      const result = await getUser();

      if (!cancelled) setData(result);
    } catch (err) {
      if (!cancelled) setError(err.message);
    } finally {
      if (!cancelled) setLoading(false);
    }
  };

  load();

  return () => {
    cancelled = true;
  };
}, []);
```

> Use a cancellation flag for non-fetch async logic. For network requests, prefer AbortController.

---

### 3. Request Cancellation (AbortController)

Cancel in-flight requests to avoid memory leaks and stale updates.

```js id="l9x2pw"
useEffect(() => {
  const controller = new AbortController();

  const load = async () => {
    try {
      const data = await getUser({ signal: controller.signal });
      setData(data);
    } catch (err) {
      if (err.name === "AbortError") return;
      setError(err.message);
    }
  };

  load();
  return () => controller.abort();
}, [userId]);
```

---

### 4. Retry with Exponential Backoff

Retry only transient failures (5xx or network errors).

```js id="8n3zcf"
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const fetchWithBackoff = async (fn, retries = 3, delay = 300) => {
  try {
    return await fn();
  } catch (err) {
    const isAbort = err.name === "AbortError";
    const isHttpError = typeof err.status === "number";
    const isRetryable = !isAbort && (!isHttpError || err.status >= 500);

    if (retries <= 0 || !isRetryable) throw err;

    const nextDelay = delay * 2 + Math.random() * 100;
    await sleep(nextDelay);

    return fetchWithBackoff(fn, retries - 1, nextDelay);
  }
};
```

---

### 5. Debounced API Calls

Avoid excessive API calls (e.g., search inputs).

```js id="i2r7wq"
const useDebounce = (value, delay = 400) => {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  return debounced;
};
```

---

### 6. Request Deduplication

Prevent duplicate API calls across components.

```js id="x8v4km"
const inFlight = new Map();

export const dedupedFetch = (key, fn) => {
  if (inFlight.has(key)) return inFlight.get(key);

  const promise = fn().finally(() => inFlight.delete(key));
  inFlight.set(key, promise);
  return promise;
};
```

---

## Examples

### Example 1: ML Prediction with Cancellation

```js id="n5q2pt"
const controllerRef = useRef(null);

const handlePredict = async (input) => {
  controllerRef.current?.abort();
  controllerRef.current = new AbortController();

  try {
    const result = await fetchWithBackoff(() =>
      apiClient("/predict", {
        method: "POST",
        body: JSON.stringify({ text: input }),
        signal: controllerRef.current.signal,
      })
    );

    setOutput(result);
  } catch (err) {
    if (err.name === "AbortError") return;
    setError(err.message);
  }
};
```

---

### Example 2: Debounced Search

```js id="w4z8yn"
const debouncedQuery = useDebounce(query, 400);

useEffect(() => {
  if (!debouncedQuery) return;

  const controller = new AbortController();

  searchAPI(debouncedQuery, { signal: controller.sign
