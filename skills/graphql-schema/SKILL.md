---
name: graphql-schema
description: GraphQL queries, mutations, and code generation patterns. Use when creating GraphQL operations, working with Apollo Client, or generating types. 
category: Creative & Media
source: antigravity
tags: [typescript, react, claude, ai, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/graphql-schema
---


# GraphQL Schema Patterns
## When to Use

Use this skill when you need graphQL queries, mutations, and code generation patterns. Use when creating GraphQL operations, working with Apollo Client, or generating types.


## Core Rules

1. **NEVER inline `gql` literals** - Create `.gql` files
2. **ALWAYS run codegen** after creating/modifying `.gql` files
3. **ALWAYS add `onError` handler** to mutations
4. **Use generated hooks** - Never write raw Apollo hooks

## File Structure

```
src/
├── components/
│   └── ItemList/
│       ├── ItemList.tsx
│       ├── GetItems.gql           # Query definition
│       └── GetItems.generated.ts  # Auto-generated (don't edit)
└── graphql/
    └── mutations/
        └── CreateItem.gql         # Shared mutations
```

## Creating a Query

### Step 1: Create .gql file

```graphql
# src/components/ItemList/GetItems.gql
query GetItems($limit: Int, $offset: Int) {
  items(limit: $limit, offset: $offset) {
    id
    name
    description
    createdAt
  }
}
```

### Step 2: Run codegen

```bash
npm run gql:typegen
```

### Step 3: Import and use generated hook

```typescript
import { useGetItemsQuery } from './GetItems.generated';

const ItemList = () => {
  const { data, loading, error, refetch } = useGetItemsQuery({
    variables: { limit: 20, offset: 0 },
  });

  if (error) return <ErrorState error={error} onRetry={refetch} />;
  if (loading && !data) return <LoadingSkeleton />;
  if (!data?.items.length) return <EmptyState />;

  return <List items={data.items} />;
};
```

## Creating a Mutation

### Step 1: Create .gql file

```graphql
# src/graphql/mutations/CreateItem.gql
mutation CreateItem($input: CreateItemInput!) {
  createItem(input: $input) {
    id
    name
    description
  }
}
```

### Step 2: Run codegen

```bash
npm run gql:typegen
```

### Step 3: Use with REQUIRED error handling

```typescript
import { useCreateItemMutation } from 'graphql/mutations/CreateItem.generated';

const CreateItemForm = () => {
  const [createItem, { loading }] = useCreateItemMutation({
    // Success handling
    onCompleted: (data) => {
      toast.success({ title: 'Item created' });
      navigation.goBack();
    },
    // ERROR HANDLING IS REQUIRED
    onError: (error) => {
      console.error('createItem failed:', error);
      toast.error({ title: 'Failed to create item' });
    },
    // Cache update
    update: (cache, { data }) => {
      if (data?.createItem) {
        cache.modify({
          fields: {
            items: (existing = []) => [...existing, data.createItem],
          },
        });
      }
    },
  });

  return (
    <Button
      onPress={() => createItem({ variables: { input: formValues } })}
      isDisabled={!isValid || loading}
      isLoading={loading}
    >
      Create
    </Button>
  );
};
```

## Mutation UI Requirements

**CRITICAL: Every mutation trigger must:**

1. **Be disabled during mutation** - Prevent double-clicks
2. **Show loading state** - Visual feedback
3. **Have onError handler** - User knows it failed
4. **Show success feedback** - User knows it worked

```typescript
// CORRECT - Complete mutation pattern
const [submit, { loading }] = useSubmitMutation({
  onError: (error) => {
    console.error('submit failed:', error);
    toast.error({ title: 'Save failed' });
  },
  onCompleted: () => {
    toast.success({ title: 'Saved' });
  },
});

<Button
  onPress={handleSubmit}
  isDisabled={!isValid || loading}
  isLoading={loading}
>
  Submit
</Button>
```

## Query Options

### Fetch Policies

| Policy | Use When |
|--------|----------|
| `cache-first` | Data rarely changes |
| `cache-and-network` | Want fast + fresh (default) |
| `network-only` | Always need latest |
| `no-cache` | Never cache (rare) |

### Common Options

```typescript
useGetItemsQuery({
  variables: { id: itemId },

  // Fetch strategy
  fetchPolicy: 'cache-and-network',

  // Re-render on network status changes
  notifyOnNetworkStatusChange: true,

  // Skip if condition not met
  skip: !itemId,

  // Poll for updates
  pollInterval: 30000,
});
```

## Optimistic Updates

For instant UI feedback:

```typescript
const [toggleFavorite] = useToggleFavoriteMutation({
  optimisticResponse: {
    toggleFavorite: {
      __typename: 'Item',
      id: itemId,
      isFavorite: !currentState,
    },
  },
  onError: (error) => {
    // Rollback happens automatically
    console.error('toggleFavorite failed:', error);
    toast.error({ title: 'Failed to update' });
  },
});
```

### When NOT to Use Optimistic Updates

- Operations that can fail validation
- Operations with server-generated values
- Destructive operations (delete)
- Operations affecting other users

## Fragments

For reusable field selections:

```graphql
# src/graphql/fragments/ItemFields.gql
fragment ItemFields on Item {
  id
  name
  description
  createdAt
  updatedAt
}
```

Use in queries:

```graphql
query GetItems {
  items {
    ...ItemFields
  }
}
```

## Anti-Patterns

```typescript
// WRONG - Inline gq
