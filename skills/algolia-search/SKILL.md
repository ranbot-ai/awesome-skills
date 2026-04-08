---
name: algolia-search
description: Expert patterns for Algolia search implementation, indexing strategies, React InstantSearch, and relevance tuning 
category: Document Processing
source: antigravity
tags: [javascript, react, nextjs, api, ai, template, document, image, security, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/algolia-search
---


# Algolia Search Integration

Expert patterns for Algolia search implementation, indexing strategies, React InstantSearch, and relevance tuning

## Patterns

### React InstantSearch with Hooks

Modern React InstantSearch setup using hooks for type-ahead search.

Uses react-instantsearch-hooks-web package with algoliasearch client.
Widgets are components that can be customized with classnames.

Key hooks:
- useSearchBox: Search input handling
- useHits: Access search results
- useRefinementList: Facet filtering
- usePagination: Result pagination
- useInstantSearch: Full state access

### Code_example

// lib/algolia.ts
import algoliasearch from 'algoliasearch/lite';

export const searchClient = algoliasearch(
  process.env.NEXT_PUBLIC_ALGOLIA_APP_ID!,
  process.env.NEXT_PUBLIC_ALGOLIA_SEARCH_KEY!  // Search-only key!
);

export const INDEX_NAME = 'products';

// components/Search.tsx
'use client';
import { InstantSearch, SearchBox, Hits, Configure } from 'react-instantsearch';
import { searchClient, INDEX_NAME } from '@/lib/algolia';

function Hit({ hit }: { hit: ProductHit }) {
  return (
    <article>
      <h3>{hit.name}</h3>
      <p>{hit.description}</p>
      <span>${hit.price}</span>
    </article>
  );
}

export function ProductSearch() {
  return (
    <InstantSearch searchClient={searchClient} indexName={INDEX_NAME}>
      <Configure hitsPerPage={20} />
      <SearchBox
        placeholder="Search products..."
        classNames={{
          root: 'relative',
          input: 'w-full px-4 py-2 border rounded',
        }}
      />
      <Hits hitComponent={Hit} />
    </InstantSearch>
  );
}

// Custom hook usage
import { useSearchBox, useHits, useInstantSearch } from 'react-instantsearch';

function CustomSearch() {
  const { query, refine } = useSearchBox();
  const { hits } = useHits<ProductHit>();
  const { status } = useInstantSearch();

  return (
    <div>
      <input
        value={query}
        onChange={(e) => refine(e.target.value)}
        placeholder="Search..."
      />
      {status === 'loading' && <p>Loading...</p>}
      <ul>
        {hits.map((hit) => (
          <li key={hit.objectID}>{hit.name}</li>
        ))}
      </ul>
    </div>
  );
}

### Anti_patterns

- Pattern: Using Admin API key in frontend code | Why: Admin key exposes full index control including deletion | Fix: Use search-only API key with restrictions
- Pattern: Not using /lite client for frontend | Why: Full client includes unnecessary code for search | Fix: Import from algoliasearch/lite for smaller bundle

### References

- https://www.algolia.com/doc/api-reference/widgets/react
- https://www.algolia.com/doc/libraries/javascript/v5/methods/search/

### Next.js Server-Side Rendering

SSR integration for Next.js with react-instantsearch-nextjs package.

Use <InstantSearchNext> instead of <InstantSearch> for SSR.
Supports both Pages Router and App Router (experimental).

Key considerations:
- Set dynamic = 'force-dynamic' for fresh results
- Handle URL synchronization with routing prop
- Use getServerState for initial state

### Code_example

// app/search/page.tsx
import { InstantSearchNext } from 'react-instantsearch-nextjs';
import { searchClient, INDEX_NAME } from '@/lib/algolia';
import { SearchBox, Hits, RefinementList } from 'react-instantsearch';

// Force dynamic rendering for fresh search results
export const dynamic = 'force-dynamic';

export default function SearchPage() {
  return (
    <InstantSearchNext
      searchClient={searchClient}
      indexName={INDEX_NAME}
      routing={{
        router: {
          cleanUrlOnDispose: false,
        },
      }}
    >
      <div className="flex gap-8">
        <aside className="w-64">
          <h3>Categories</h3>
          <RefinementList attribute="category" />
          <h3>Brand</h3>
          <RefinementList attribute="brand" />
        </aside>
        <main className="flex-1">
          <SearchBox placeholder="Search products..." />
          <Hits hitComponent={ProductHit} />
        </main>
      </div>
    </InstantSearchNext>
  );
}

// For custom routing (URL synchronization)
import { history } from 'instantsearch.js/es/lib/routers';
import { simple } from 'instantsearch.js/es/lib/stateMappings';

<InstantSearchNext
  searchClient={searchClient}
  indexName={INDEX_NAME}
  routing={{
    router: history({
      getLocation: () =>
        typeof window === 'undefined'
          ? new URL(url) as unknown as Location
          : window.location,
    }),
    stateMapping: simple(),
  }}
>
  {/* widgets */}
</InstantSearchNext>

### Anti_patterns

- Pattern: Using InstantSearch component for Next.js SSR | Why: Regular component doesn't support server-side rendering | Fix: Use InstantSearchNext from react-instantsearch-nextjs
- Pattern: Static rendering for search pages | Why: Search results must be fresh for each request | Fix: Set export const dynamic = 'force-dynamic'

### References

- https://www.npmjs.com/package/react-instantsearch-nextjs
- 
