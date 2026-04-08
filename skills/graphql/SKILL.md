---
name: graphql
description: GraphQL gives clients exactly the data they need - no more, no less. One endpoint, typed schema, introspection. But the flexibility that makes it powerful also makes it dangerous. Without proper contr
category: Document Processing
source: antigravity
tags: [typescript, react, node, nextjs, api, ai, design, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/graphql
---


# GraphQL

GraphQL gives clients exactly the data they need - no more, no less. One
endpoint, typed schema, introspection. But the flexibility that makes it
powerful also makes it dangerous. Without proper controls, clients can
craft queries that bring down your server.

This skill covers schema design, resolvers, DataLoader for N+1 prevention,
federation for microservices, and client integration with Apollo/urql.
Key insight: GraphQL is a contract. The schema is the API documentation.
Design it carefully.

2025 lesson: GraphQL isn't always the answer. For simple CRUD, REST is
simpler. For high-performance public APIs, REST with caching wins. Use
GraphQL when you have complex data relationships and diverse client needs.

## Principles

- Schema-first design - the schema is the contract
- Prevent N+1 queries with DataLoader
- Limit query depth and complexity
- Use fragments for reusable selections
- Mutations should be specific, not generic update operations
- Errors are data - use union types for expected failures
- Nullability is meaningful - design it intentionally

## Capabilities

- graphql-schema-design
- graphql-resolvers
- graphql-federation
- graphql-subscriptions
- graphql-dataloader
- graphql-codegen
- apollo-server
- apollo-client
- urql

## Scope

- database-queries -> postgres-wizard
- authentication -> authentication-oauth
- rest-api-design -> backend
- websocket-infrastructure -> backend

## Tooling

### Server

- @apollo/server - When: Apollo Server v4 Note: Most popular GraphQL server
- graphql-yoga - When: Lightweight alternative Note: Good for serverless
- mercurius - When: Fastify integration Note: Fast, uses JIT

### Client

- @apollo/client - When: Full-featured client Note: Caching, state management
- urql - When: Lightweight alternative Note: Smaller, simpler
- graphql-request - When: Simple requests Note: Minimal, no caching

### Tools

- graphql-codegen - When: Type generation Note: Essential for TypeScript
- dataloader - When: N+1 prevention Note: Batches and caches

## Patterns

### Schema Design

Type-safe schema with proper nullability

**When to use**: Designing any GraphQL API

# SCHEMA DESIGN:

"""
The schema is your API contract. Design nullability
intentionally - non-null fields must always resolve.
"""

type Query {
  # Non-null - will always return user or throw
  user(id: ID!): User!

  # Nullable - returns null if not found
  userByEmail(email: String!): User

  # Non-null list with non-null items
  users(limit: Int = 10, offset: Int = 0): [User!]!

  # Search with pagination
  searchUsers(
    query: String!
    first: Int
    after: String
  ): UserConnection!
}

type Mutation {
  # Input types for complex mutations
  createUser(input: CreateUserInput!): CreateUserPayload!
  updateUser(id: ID!, input: UpdateUserInput!): UpdateUserPayload!
  deleteUser(id: ID!): DeleteUserPayload!
}

type Subscription {
  userCreated: User!
  messageReceived(roomId: ID!): Message!
}

# Input types
input CreateUserInput {
  email: String!
  name: String!
  role: Role = USER
}

input UpdateUserInput {
  email: String
  name: String
  role: Role
}

# Payload types (for errors as data)
type CreateUserPayload {
  user: User
  errors: [Error!]!
}

union UpdateUserPayload = UpdateUserSuccess | NotFoundError | ValidationError

type UpdateUserSuccess {
  user: User!
}

# Enums
enum Role {
  USER
  ADMIN
  MODERATOR
}

# Types with relationships
type User {
  id: ID!
  email: String!
  name: String!
  role: Role!
  posts(limit: Int = 10): [Post!]!
  createdAt: DateTime!
}

type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
  comments: [Comment!]!
  published: Boolean!
}

# Pagination (Relay-style)
type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

type UserEdge {
  node: User!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  hasPreviousPage: Boolean!
  startCursor: String
  endCursor: String
}

### DataLoader for N+1 Prevention

Batch and cache database queries

**When to use**: Resolving relationships

# DATALOADER:

"""
Without DataLoader, fetching 10 posts with authors
makes 11 queries (1 for posts + 10 for each author).
DataLoader batches into 2 queries.
"""

import DataLoader from 'dataloader';

// Create loaders per request
function createLoaders(db) {
  return {
    userLoader: new DataLoader(async (ids) => {
      // Single query for all users
      const users = await db.user.findMany({
        where: { id: { in: ids } }
      });

      // Return in same order as ids
      const userMap = new Map(users.map(u => [u.id, u]));
      return ids.map(id => userMap.get(id) || null);
    }),

    postsByAuthorLoader: new DataLoader(async (authorIds) => {
      const posts = await db.post.findMany({
        where: { authorId: { in: authorIds } }
      });

      // Group by author
      const postsByAuthor = new Map();
      posts.forEach(post => {
        const existing = postsByAuthor.get(post.authorId) || [];
       
