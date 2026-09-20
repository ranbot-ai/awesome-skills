---
name: firebase-app-platform
description: Build and operate apps on Firebase using Auth, Firestore, Cloud Functions, and Hosting. Use when building mobile/web backends with managed services, real-time data sync, or serverless APIs. 
category: Document Processing
source: antigravity
tags: [javascript, typescript, node, api, ai, agent, template, document, security, firebase]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/firebase-app-platform
---


# Firebase App Platform

Ship mobile and web backends with Firebase managed services.

## When to Use This Skill

Use this skill when:
- Building mobile or web apps with real-time data sync
- Need authentication with minimal backend code
- Prototyping quickly with managed infrastructure
- Building serverless APIs with Cloud Functions
- Hosting static sites or SPAs with CDN

## Prerequisites

- Node.js 18+
- Firebase CLI (`npm install -g firebase-tools`)
- Google Cloud account (Firebase is part of GCP)
- A Firebase project (create at console.firebase.google.com)

## Quick Start

```bash
# Install and authenticate
npm install -g firebase-tools
firebase login

# Initialize in your project directory
firebase init
# Select: Firestore, Functions, Hosting, Emulators

# Start local emulators
firebase emulators:start

# Deploy everything
firebase deploy

# Deploy specific services
firebase deploy --only functions
firebase deploy --only hosting
firebase deploy --only firestore:rules
```

## Firestore Database

### Security Rules

```javascript
// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }

    // Messages: authenticated users can read, only owner can write
    match /channels/{channelId}/messages/{messageId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null
        && request.resource.data.userId == request.auth.uid
        && request.resource.data.body is string
        && request.resource.data.body.size() <= 5000;
      allow update, delete: if request.auth != null
        && resource.data.userId == request.auth.uid;
    }

    // Admin-only collection
    match /admin/{document=**} {
      allow read, write: if request.auth != null
        && get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }

    // Default: deny everything
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

### Data Operations

```typescript
// lib/firestore.ts
import { getFirestore, collection, doc, setDoc, getDoc,
         query, where, orderBy, limit, onSnapshot,
         serverTimestamp, increment } from "firebase/firestore";

const db = getFirestore();

// Create document with auto-ID
async function createMessage(channelId: string, body: string, userId: string) {
  const ref = doc(collection(db, "channels", channelId, "messages"));
  await setDoc(ref, {
    body,
    userId,
    createdAt: serverTimestamp(),
  });
  return ref.id;
}

// Real-time listener
function subscribeToMessages(channelId: string, callback: (msgs: any[]) => void) {
  const q = query(
    collection(db, "channels", channelId, "messages"),
    orderBy("createdAt", "desc"),
    limit(50)
  );
  return onSnapshot(q, (snapshot) => {
    const messages = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    callback(messages);
  });
}

// Atomic counter
async function incrementViews(postId: string) {
  await setDoc(doc(db, "posts", postId), {
    views: increment(1),
  }, { merge: true });
}
```

### Indexes

```json
// firestore.indexes.json
{
  "indexes": [
    {
      "collectionGroup": "messages",
      "queryScope": "COLLECTION",
      "fields": [
        { "fieldPath": "channelId", "order": "ASCENDING" },
        { "fieldPath": "createdAt", "order": "DESCENDING" }
      ]
    }
  ]
}
```

## Authentication

```typescript
// lib/auth.ts
import { getAuth, signInWithPopup, GoogleAuthProvider,
         createUserWithEmailAndPassword, signInWithEmailAndPassword,
         signOut, onAuthStateChanged } from "firebase/auth";

const auth = getAuth();

// Google sign-in
async function signInWithGoogle() {
  const provider = new GoogleAuthProvider();
  const result = await signInWithPopup(auth, provider);
  return result.user;
}

// Email/password registration
async function register(email: string, password: string) {
  const result = await createUserWithEmailAndPassword(auth, email, password);
  return result.user;
}

// Auth state listener
onAuthStateChanged(auth, (user) => {
  if (user) {
    console.log("Signed in:", user.uid, user.email);
  } else {
    console.log("Signed out");
  }
});
```

## Cloud Functions

```typescript
// functions/src/index.ts
import { onRequest } from "firebase-functions/v2/https";
import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { getFirestore } from "firebase-admin/firestore";
import { initializeApp } from "firebase-admin/app";

initializeApp();
const db = getFirestore();

// HTTP function (API endpoint)
export const api = onRequest({ cors: true, region: "us-central1" }, async (req, res) => {
  if (req.method !== "GET") {
    res.status(405).send("Method not allowed");
    return;
  }
  const snapshot = await db.collection("posts").orderBy("createdAt", "desc").limit(10).get();
  const p
