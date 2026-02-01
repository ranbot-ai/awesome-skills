---
name: javascript-typescript-typescript-scaffold
description: You are a TypeScript project architecture expert specializing in scaffolding production-ready Node.js and frontend applications. Generate complete project structures with modern tooling (pnpm, Vite, N
category: Document Processing
source: antigravity
tags: [javascript, typescript, react, node, nextjs, api, ai, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/javascript-typescript-typescript-scaffold
---


# TypeScript Project Scaffolding

You are a TypeScript project architecture expert specializing in scaffolding production-ready Node.js and frontend applications. Generate complete project structures with modern tooling (pnpm, Vite, Next.js), type safety, testing setup, and configuration following current best practices.

## Use this skill when

- Working on typescript project scaffolding tasks or workflows
- Needing guidance, best practices, or checklists for typescript project scaffolding

## Do not use this skill when

- The task is unrelated to typescript project scaffolding
- You need a different domain or tool outside this scope

## Context

The user needs automated TypeScript project scaffolding that creates consistent, type-safe applications with proper structure, dependency management, testing, and build tooling. Focus on modern TypeScript patterns and scalable architecture.

## Requirements

$ARGUMENTS

## Instructions

### 1. Analyze Project Type

Determine the project type from user requirements:
- **Next.js**: Full-stack React applications, SSR/SSG, API routes
- **React + Vite**: SPA applications, component libraries
- **Node.js API**: Express/Fastify backends, microservices
- **Library**: Reusable packages, utilities, tools
- **CLI**: Command-line tools, automation scripts

### 2. Initialize Project with pnpm

```bash
# Install pnpm if needed
npm install -g pnpm

# Initialize project
mkdir project-name && cd project-name
pnpm init

# Initialize git
git init
echo "node_modules/" >> .gitignore
echo "dist/" >> .gitignore
echo ".env" >> .gitignore
```

### 3. Generate Next.js Project Structure

```bash
# Create Next.js project with TypeScript
pnpm create next-app@latest . --typescript --tailwind --app --src-dir --import-alias "@/*"
```

```
nextjs-project/
├── package.json
├── tsconfig.json
├── next.config.js
├── .env.example
├── src/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── api/
│   │   │   └── health/
│   │   │       └── route.ts
│   │   └── (routes)/
│   │       └── dashboard/
│   │           └── page.tsx
│   ├── components/
│   │   ├── ui/
│   │   │   ├── Button.tsx
│   │   │   └── Card.tsx
│   │   └── layout/
│   │       ├── Header.tsx
│   │       └── Footer.tsx
│   ├── lib/
│   │   ├── api.ts
│   │   ├── utils.ts
│   │   └── types.ts
│   └── hooks/
│       ├── useAuth.ts
│       └── useFetch.ts
└── tests/
    ├── setup.ts
    └── components/
        └── Button.test.tsx
```

**package.json**:
```json
{
  "name": "nextjs-project",
  "version": "0.1.0",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "test": "vitest",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    "next": "^14.1.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/node": "^20.11.0",
    "@types/react": "^18.2.0",
    "typescript": "^5.3.0",
    "vitest": "^1.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "eslint": "^8.56.0",
    "eslint-config-next": "^14.1.0"
  }
}
```

**tsconfig.json**:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "jsx": "preserve",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "allowJs": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "incremental": true,
    "paths": {
      "@/*": ["./src/*"]
    },
    "plugins": [{"name": "next"}]
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
```

### 4. Generate React + Vite Project Structure

```bash
# Create Vite project
pnpm create vite . --template react-ts
```

**vite.config.ts**:
```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './tests/setup.ts',
  },
})
```

### 5. Generate Node.js API Project Structure

```
nodejs-api/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts
│   ├── app.ts
│   ├── config/
│   │   ├── database.ts
│   │   └── env.ts
│   ├── routes/
│   │   ├── index.ts
│   │   ├── users.ts
│   │   └── health.ts
│   ├── controllers/
│   │   └── userController.ts
│   ├── services/
│   │   └── userService.ts
│   ├── models/
│   │   └── User.ts
│   ├── middleware/
│   │   ├── auth.ts
│   │   └── errorHandler.ts
│   └── types/
│       └── express.d.ts
└── tests/
    └── routes/
        └── users.test.ts
```

**package.json for Node.js API**:
```json
{
  "name": "nodejs-api",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "v
