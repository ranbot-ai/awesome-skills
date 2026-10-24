---
name: circleci
description: Configure CircleCI workflows and orbs for continuous integration and deployment. 
category: AI & Agents
source: antigravity
tags: [node, ai, agent, workflow, template, image, security, docker, kubernetes, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/circleci
---


# CircleCI

Build, test, and deploy applications using CircleCI's cloud-native CI/CD platform.

## When to Use This Skill

Use this skill when:
- Setting up CI/CD pipelines with CircleCI
- Using orbs for reusable configuration
- Optimizing build times with caching and parallelism
- Configuring CircleCI workflows and approvals
- Managing CircleCI contexts and secrets

## Prerequisites

- CircleCI account connected to repository
- Project enabled in CircleCI dashboard
- Basic YAML understanding

## CI trust and example scope

Fragments below are separate examples and often omit required executor/install/report setup; validate the combined configuration with the installed CircleCI schema and inspect expanded orbs. Pin reviewed orb/image versions compatible with current runners. Restrict secret contexts/deploy jobs to trusted branches and approved identities; an approval job must depend on the actual build artifact producer as well as tests. Do not allow untrusted PRs to poison privileged caches/workspaces. Protect/redact logs and artifacts and state tests not run when timing/report data is missing.

## Configuration File

Create `.circleci/config.yml`:

```yaml
version: 2.1

orbs:
  node: circleci/node@5.2
  docker: circleci/docker@2.4

executors:
  default:
    docker:
      - image: cimg/node:20.10
    working_directory: ~/project

jobs:
  build:
    executor: default
    steps:
      - checkout
      - node/install-packages:
          pkg-manager: npm
      - run:
          name: Build application
          command: npm run build
      - persist_to_workspace:
          root: .
          paths:
            - dist

  test:
    executor: default
    steps:
      - checkout
      - node/install-packages:
          pkg-manager: npm
      - run:
          name: Run tests
          command: npm test

  deploy:
    executor: default
    steps:
      - checkout
      - attach_workspace:
          at: .
      - run:
          name: Deploy
          command: ./deploy.sh

workflows:
  build-test-deploy:
    jobs:
      - build
      - test:
          requires:
            - build
      - deploy:
          requires:
            - test
          filters:
            branches:
              only: main
```

## Executors

### Docker Executor

```yaml
executors:
  node:
    docker:
      - image: cimg/node:20.10
      - image: cimg/postgres:15.0
        environment:
          POSTGRES_USER: test
          POSTGRES_DB: testdb
    working_directory: ~/app
```

### Machine Executor

```yaml
executors:
  linux-machine:
    machine:
      image: ubuntu-2204:current
    resource_class: large
```

### macOS Executor

```yaml
executors:
  macos:
    macos:
      xcode: "15.0.0"
    resource_class: macos.m1.medium.gen1
```

## Caching

### Dependency Caching

```yaml
jobs:
  build:
    steps:
      - checkout
      - restore_cache:
          keys:
            - v1-deps-{{ checksum "package-lock.json" }}
            - v1-deps-
      - run: npm ci
      - save_cache:
          key: v1-deps-{{ checksum "package-lock.json" }}
          paths:
            - node_modules
```

### Multi-Key Caching

```yaml
- restore_cache:
    keys:
      - v1-{{ .Branch }}-{{ checksum "package-lock.json" }}
      - v1-{{ .Branch }}-
      - v1-main-
      - v1-
```

## Workspaces

### Persist Data

```yaml
jobs:
  build:
    steps:
      - checkout
      - run: npm run build
      - persist_to_workspace:
          root: .
          paths:
            - dist
            - node_modules

  deploy:
    steps:
      - attach_workspace:
          at: ~/project
      - run: ./deploy.sh
```

## Parallelism

### Test Splitting

```yaml
jobs:
  test:
    parallelism: 4
    steps:
      - checkout
      - run:
          name: Run tests
          command: |
            TESTFILES=$(circleci tests glob "test/**/*.test.js" | circleci tests split --split-by=timings)
            npm test -- $TESTFILES
      - store_test_results:
          path: test-results
```

## Workflows

### Sequential Jobs

```yaml
workflows:
  pipeline:
    jobs:
      - build
      - test:
          requires:
            - build
      - deploy:
          requires:
            - test
```

### Parallel Jobs

```yaml
workflows:
  pipeline:
    jobs:
      - build
      - test-unit:
          requires:
            - build
      - test-integration:
          requires:
            - build
      - deploy:
          requires:
            - test-unit
            - test-integration
```

### Manual Approval

```yaml
workflows:
  deploy-prod:
    jobs:
      - build
      - test
      - hold:
          type: approval
          requires:
            - build
            - test
      - deploy-production:
          requires:
            - hold
```

### Scheduled Workflows

```yaml
workflows:
  nightly:
    triggers:
      - schedule:
          cron: "0 2 * * *"
          filters:
            branches:
              only:
                - main
    jobs:
      - build
      - test
```

### Branch Filtering

```ya
