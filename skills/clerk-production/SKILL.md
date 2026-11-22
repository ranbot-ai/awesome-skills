---
name: clerk-production
description: Setting up or changing Clerk sign-in, organizations, roles or billing on Next.js, or sign-in that does nothing or lands wrong: Clerk in production. 
category: Document Processing
source: antigravity
tags: [nextjs, api, mcp, ai, agent, design, document, security, supabase, stripe]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/clerk-production
---


# Clerk in production: the choices its own skills cannot make

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

Setting up or changing Clerk sign-in, organizations, roles or billing on Next.js, or sign-in that does nothing or lands wrong: Clerk in production.


This skill covers Clerk from the first setup on its development instance through production.

**Decide the product's access model before following Clerk's API guidance.** Clerk's own agent skills know the API. They cannot decide:

- where a session is verified, and what may read it;
- what a workspace is;
- where billing ends and authorization begins;
- which dashboard settings silently change what your code is allowed to do.

Those decisions are here.

**Where Clerk's defaults or quickstarts contradict this skill, this skill wins.** These mechanics use Next.js App Router, Next 16 (`proxy.ts` middleware), Clerk Core 3 (`@clerk/nextjs` v7), Supabase and Netlify. Apply `saas-authorization` for the access model, which carries to any identity provider.

**Use the product's integration notes, permission module and member home.** Integration notes hold dated provider configuration: instances, settings, slugs and read-backs. The permission module maps roles to permission strings. The member home is the sign-in destination, `/dashboard` unless the product names another.

## Clerk's own skills: get them, prefer them for the API

- **Use Clerk's own skills for its API.** The set comes from the GitHub repository `clerk/skills`:
  - `clerk` (a router);
  - `clerk-setup`, `clerk-nextjs-patterns`, `clerk-custom-ui`, `clerk-orgs`, `clerk-billing`, `clerk-webhooks`, `clerk-testing`;
  - `clerk-backend-api` (browse and call the Backend API);
  - `clerk-cli`.
- **Install and vendor the skills instead of relying on API memory.** Run `npx skills add clerk/skills` with the open `skills` CLI. Vendor them into the product's skills folder so they load whenever Clerk is touched, and prefer them over training-era memory of the API.
- **Pin the skills and update them deliberately.** A `skills-lock.json` records each skill's source, its path and a content hash. `npx skills update` refreshes them on purpose.
- **Refuse vendor suggestions that contradict this skill.** These include:
  - `createRouteMatcher` path lists;
  - `<SignedIn>` and `<SignedOut>`, which Core 3 deleted;
  - `<ClerkProvider dynamic>`;
  - rebuilt sign-in screens;
  - `clerk.signIn()` in the browser suite;
  - Clerk permissions with features attached;
  - a hand-written CSP.

## The choices

1. **Verify, never decode, always behind one session seam.** Use `SessionVerifier`. Tests substitute a mock verifier when `CLERK_SECRET_KEY` is absent; keyless mode is for development only. → `references/sessions-and-front-door.md § Sessions`
2. **Store Clerk ids only.** Read names and emails from Clerk at render time. Only the `workspaces` table holds a Clerk org or user id, and, where the product records authorship, one member table beside it holds the user id too (`saas-authorization`).
3. **Authorization lives with the data, not in a path list.** Clerk v7 deprecates `createRouteMatcher`, and `proxy.ts` only attaches the session. Every protected page and every action checks for itself; a check in a layout alone is not a check.
4. **Clerk's own components are the sign-in surface.** Use `<SignIn />`, `<SignUp />`, `<UserButton />`. They are dressed through `appearance`, never rebuilt.
5. **Sign-in lands on the member home, never on `/`.**
   - `signInFallbackRedirectUrl` and `signUpFallbackRedirectUrl` name the member home, and `afterSignOutUrl` is `/`.
   - The member home sends a signed-out visitor to `/sign-in` with a `redirect_url` back to itself.
   - The root `<ClerkProvider>` takes `nonce`, never `dynamic`: the root layout reads it from the request's `content-security-policy` header, the `'nonce-…'` in `script-src` (`references/sessions-and-front-door.md`).
6. **The front door reads no session.** `/` and every public page never call `auth()`, the seam or `<Show>`, and a signed-in visitor is never redirected away. The header's one button is labelled from the `__client_uat` cookie. → `references/sessions-and-front-door.md § The front door and the member home`
7. **In the organization shape, *Membership required* goes on at setup, before the first migration.** The authenticated harness then creates each test account's organization. In the individual shape, organizations stay off. → `references/organizations-and-billing.md § Organizations`
8. **Organization management is Clerk's own modal.** Never build a separate page. What it lacks goes in as a
