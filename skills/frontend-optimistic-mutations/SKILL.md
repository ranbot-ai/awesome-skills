---
name: frontend-optimistic-mutations
description: A portable, framework-agnostic discipline for the write path of any React or React Native app using a query/cache layer. 
category: Document Processing
source: antigravity
tags: [react, api, claude, ai, agent, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/frontend-optimistic-mutations
---


# Frontend Optimistic Mutations (the write path)
## When to Use

Use this skill when you need a portable, framework-agnostic discipline for the write path of any React or React Native app using a query/cache layer. Codifies the optimistic-update lifecycle (cancel in-flight queries → snapshot every affected cache → patch instantly → roll back verbatim on error → invalidate on...


> Portable skill — readable by Claude Code, OpenCode, Codex, Cursor, Windsurf, and others.
> This skill describes the **discipline of the write path** — optimistic updates, rollback,
> idempotency, cache coherence — not a UI library or a styling system. It builds directly on the
> **frontend-data-contracts** skill (writes go through the typed client) and the
> **frontend-architecture** skill (mutations live in `modules/{feature}/hooks/`, keyed by a factory).

The goal: a write **feels instant** (the UI reflects it before the server confirms), is **safe**
(a failure restores the exact prior state, and a retry never double-charges), and leaves the cache
**coherent** (the detail view and every list page agree). All three at once — that's the craft.

---

## 0. The five core ideas

1. **The optimistic lifecycle is fixed.** cancel → snapshot → patch → (error: roll back) → (settle: invalidate). Every optimistic mutation follows the same five beats.
2. **Roll back verbatim.** On failure, restore the exact snapshot taken before the patch — not a "best guess" re-derivation. Keep the snapshot in mutation context.
3. **Idempotency is generated once, not per attempt.** The key is created at form init (or first intent), so a network retry replays the original server response instead of performing the action twice.
4. **Caches move in lock-step.** A status change patches the detail cache **and** every list page that contains the entity, so badges never disagree across surfaces.
5. **Server state never enters the client store.** Optimistic state lives in the query cache, not Zustand/Redux. The cache is the single source of truth for server data (per frontend-architecture §4).

---

## 1. When to be optimistic (and when not)

| Situation                                                                     | Strategy                                                                                                                       |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| High-confidence, low-conflict write (toggle status, like, mark-paid, reorder) | **Optimistic** — patch immediately, roll back on error.                                                                        |
| Create that returns a server-generated id/number/total                        | **Pending state**, then `setQueryData` from the server response. A temporary optimistic row is optional; reconcile on success. |
| Destructive or hard-to-reverse write (delete with cascade, send money)        | **Confirm first**, then optimistic _or_ pending — never silent-optimistic.                                                     |
| Write whose result the user can't see yet (background job)                    | **Pending + toast**, invalidate when done. No optimistic patch.                                                                |

Optimism is a UX tool for writes you're confident will succeed. If failure is common or expensive to
undo, prefer a pending state.

---

## 2. The optimistic lifecycle (TanStack Query)

The canonical shape. Each beat has a job; skipping one breaks correctness.

```ts
// modules/invoice/hooks/useInvoiceMutations.ts
interface MarkPaidContext {
  previousInvoice: Invoice | undefined; // detail snapshot
  previousLists: Array<[readonly unknown[], InvoiceListResponse]>; // every list page snapshot
}

export function useMarkInvoicePaid() {
  const queryClient = useQueryClient();
  const notifyError = useApiErrorToast();

  return useMutation<Invoice, ApiError, { id: InvoiceId }, MarkPaidContext>({
    mutationFn: ({ id }) => apiClient.post<Invoice>(INVOICE_API.markPaid(id)),

    // 1 + 2 + 3: cancel in-flight reads, snapshot, patch
    onMutate: async ({ id }) => {
      await queryClient.cancelQueries({ queryKey: invoiceKeys.all }); // (1) no late refetch clobber

      const detailKey = invoiceKeys.detail(id);
      const previousInvoice = queryClient.getQueryData<Invoice>(detailKey); // (2) snapshot detail
      if (previousInvoice) {
        queryClient.setQueryData<Invoice>(detailKey, {
          // (3) patch detail
          ...previousInvoice,
          status: InvoiceStatus.Paid,
        });
      }

      const previousLists: MarkPaidContext["previousLists"] = [];
      for (const [key, list] of queryClient.getQueriesData<InvoiceListResponse>(
        {
          queryKey: invoiceKeys.lists(),
        },
      )) {
        if (!list) continue;
        previousLists.push([key, li
