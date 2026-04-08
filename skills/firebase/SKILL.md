---
name: firebase
description: Firebase gives you a complete backend in minutes - auth, database, storage, functions, hosting. But the ease of setup hides real complexity. Security rules are your last line of defense, and they're o
category: Development & Code Tools
source: antigravity
tags: [javascript, react, node, nextjs, api, ai, agent, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/firebase
---


# Firebase

Firebase gives you a complete backend in minutes - auth, database, storage,
functions, hosting. But the ease of setup hides real complexity. Security rules
are your last line of defense, and they're often wrong. Firestore queries are
limited, and you learn this after you've designed your data model.

This skill covers Firebase Authentication, Firestore, Realtime Database, Cloud
Functions, Cloud Storage, and Firebase Hosting. Key insight: Firebase is
optimized for read-heavy, denormalized data. If you're thinking relationally,
you're thinking wrong.

2025 lesson: Firestore pricing can surprise you. Reads are cheap until they're
not. A poorly designed listener can cost more than a dedicated database. Plan
your data model for your query patterns, not your data relationships.

## Principles

- Design data for queries, not relationships
- Security rules are mandatory, not optional
- Denormalize aggressively - duplication is cheap, joins are expensive
- Batch writes and transactions for consistency
- Use offline persistence wisely - it's not free
- Cloud Functions for what clients shouldn't do
- Environment-based config, never hardcode keys in client

## Capabilities

- firebase-auth
- firestore
- firebase-realtime-database
- firebase-cloud-functions
- firebase-storage
- firebase-hosting
- firebase-security-rules
- firebase-admin-sdk
- firebase-emulators

## Scope

- general-backend-architecture -> backend
- payment-processing -> stripe
- email-sending -> email
- advanced-auth-flows -> authentication-oauth
- kubernetes-deployment -> devops

## Tooling

### Core

- firebase - When: Client-side SDK Note: Modular SDK - tree-shakeable
- firebase-admin - When: Server-side / Cloud Functions Note: Full access, bypasses security rules
- firebase-functions - When: Cloud Functions v2 Note: v2 functions are recommended

### Testing

- @firebase/rules-unit-testing - When: Testing security rules Note: Essential - rules bugs are security bugs
- firebase-tools - When: Emulator suite Note: Local development without hitting production

### Frameworks

- reactfire - When: React + Firebase Note: Hooks-based, handles subscriptions
- vuefire - When: Vue + Firebase Note: Vue-specific bindings
- angularfire - When: Angular + Firebase Note: Official Angular bindings

## Patterns

### Modular SDK Import

Import only what you need for smaller bundles

**When to use**: Client-side Firebase usage

# MODULAR IMPORTS:

"""
Firebase v9+ uses modular SDK. Import only what you need.
This enables tree-shaking and smaller bundles.
"""

// WRONG: v8-compat style (larger bundle)
import firebase from 'firebase/compat/app';
import 'firebase/compat/firestore';
const db = firebase.firestore();

// RIGHT: v9+ modular (tree-shakeable)
import { initializeApp } from 'firebase/app';
import { getFirestore, collection, doc, getDoc } from 'firebase/firestore';

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

// Get a document
const docRef = doc(db, 'users', 'userId');
const docSnap = await getDoc(docRef);

if (docSnap.exists()) {
  console.log(docSnap.data());
}

// Query with constraints
import { query, where, orderBy, limit } from 'firebase/firestore';

const q = query(
  collection(db, 'posts'),
  where('published', '==', true),
  orderBy('createdAt', 'desc'),
  limit(10)
);

### Security Rules Design

Secure your data with proper rules from day one

**When to use**: Any Firestore database

# FIRESTORE SECURITY RULES:

"""
Rules are your last line of defense. Every read and write
goes through them. Get them wrong, and your data is exposed.
"""

rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Helper functions
    function isSignedIn() {
      return request.auth != null;
    }

    function isOwner(userId) {
      return request.auth.uid == userId;
    }

    function isAdmin() {
      return request.auth.token.admin == true;
    }

    // Users collection
    match /users/{userId} {
      // Anyone can read public profile
      allow read: if true;

      // Only owner can write their own data
      allow write: if isOwner(userId);

      // Private subcollection
      match /private/{document=**} {
        allow read, write: if isOwner(userId);
      }
    }

    // Posts collection
    match /posts/{postId} {
      // Anyone can read published posts
      allow read: if resource.data.published == true
                  || isOwner(resource.data.authorId);

      // Only authenticated users can create
      allow create: if isSignedIn()
                    && request.resource.data.authorId == request.auth.uid;

      // Only author can update/delete
      allow update, delete: if isOwner(resource.data.authorId);
    }

    // Admin-only collection
    match /admin/{document=**} {
      allow read, write: if isAdmin();
    }
  }
}

### Data Modeling for Queries

Design Firestore data structure around query patterns

**When to use**: Designing Firestore schema

# FIRESTORE 
