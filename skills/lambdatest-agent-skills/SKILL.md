---
name: lambdatest-agent-skills
description: Production-grade test automation skills for 46 frameworks across E2E, unit, mobile, BDD, visual, and cloud testing in 15+ languages. 
category: AI & Agents
source: antigravity
tags: [python, typescript, react, api, claude, ai, agent, automation, workflow, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/lambdatest-agent-skills
---


# LambdaTest Agent Skills — Test Automation Registry (46 Skills)

## Overview

This skill is a curated index of 46 production-grade test automation skills sourced from the [LambdaTest/agent-skills](https://github.com/LambdaTest/agent-skills) repository. It teaches AI coding assistants how to write, structure, and execute test automation code across every major framework and 15+ programming languages. Instead of generating generic test code, the AI becomes a senior QA automation architect that understands correct project structure, dependency versions, cloud execution, CI/CD integration, and common debugging patterns for each framework.

This skill adapts material from an external GitHub repository:
- `source_repo: LambdaTest/agent-skills`
- `source_type: community`

## When to Use This Skill

- Use when you need to write, scaffold, or review test automation code for any major framework
- Use when working with Selenium, Playwright, Cypress, Jest, pytest, Appium, or any of the 46 supported frameworks
- Use when setting up a new test project and need the correct project structure, config files, and dependencies
- Use when integrating tests into a CI/CD pipeline (GitHub Actions, Jenkins, GitLab CI)
- Use when migrating tests between frameworks (e.g. Selenium → Playwright, Puppeteer → Cypress)
- Use when running tests on cloud infrastructure such as LambdaTest / TestMu AI
- Use when the user asks how to write, debug, or scale automated tests

## How It Works

### Step 1: Identify the Framework and Language

Determine which testing framework and programming language the user is working with. Match it to one of the 46 supported skills below. Each skill covers a specific framework with language-appropriate code patterns.

### Step 2: Apply the Correct Skill Context

Load the relevant framework skill from the registry below. Each skill includes: project setup and dependencies, core code patterns, page objects or test utilities, cloud execution configuration, CI/CD integration, a debugging table for common problems, and a best practices checklist.

### Step 3: Generate Production-Ready Test Code

Use the loaded skill context to generate test code that follows real-world conventions — not generic boilerplate. Apply correct import paths, configuration formats, assertion libraries, and runner commands specific to the framework and language.

### Step 4: Configure for Local or Cloud Execution

If the user wants to run tests locally, apply local runner configuration. If running on LambdaTest / TestMu AI cloud, configure RemoteWebDriver capabilities or the appropriate cloud SDK, and set `LT_USERNAME` and `LT_ACCESS_KEY` from environment variables — never hardcode credentials.

### Step 5: Add CI/CD Integration

When requested, generate a GitHub Actions (or Jenkins / GitLab CI) workflow that runs the tests in parallel, uploads reports, and captures artifacts on failure.

## Skill Registry

### 🌐 E2E / Browser Testing (15 skills)

| Skill | Languages | Description |
|---|---|---|
| `selenium-skill` | Java, Python, JS, C#, Ruby | Selenium WebDriver with cross-browser and cloud support |
| `playwright-skill` | JS, TS, Python, Java, C# | Playwright browser automation with API mocking |
| `cypress-skill` | JS, TS | Cypress E2E and component testing |
| `webdriverio-skill` | JS, TS | WebdriverIO with page objects and cloud integration |
| `puppeteer-skill` | JS, TS | Puppeteer Chrome automation |
| `testcafe-skill` | JS, TS | TestCafe cross-browser testing |
| `nightwatchjs-skill` | JS, TS | Nightwatch.js browser automation |
| `capybara-skill` | Ruby | Capybara acceptance testing |
| `geb-skill` | Groovy | Geb Groovy browser automation |
| `selenide-skill` | Java | Selenide fluent Selenium wrapper |
| `nemojs-skill` | JS | Nemo.js PayPal browser automation |
| `protractor-skill` | JS, TS | Protractor Angular E2E testing |
| `codeception-skill` | PHP | Codeception full-stack PHP testing |
| `laravel-dusk-skill` | PHP | Laravel Dusk browser testing |
| `robot-framework-skill` | Python, Robot | Robot Framework keyword-driven testing |

### 🧪 Unit Testing (15 skills)

| Skill | Languages | Description |
|---|---|---|
| `jest-skill` | JS, TS | Jest unit and integration tests with mocking |
| `junit-5-skill` | Java | JUnit 5 with parameterized tests and extensions |
| `pytest-skill` | Python | pytest with fixtures, parametrize, and plugins |
| `testng-skill` | Java | TestNG with data providers and parallel execution |
| `vitest-skill` | JS, TS | Vitest for Vite projects |
| `mocha-skill` | JS, TS | Mocha with Chai assertions |
| `jasmine-skill` | JS, TS | Jasmine BDD-style unit testing |
| `karma-skill` | JS, TS | Karma test runner |
| `xunit-skill` | C# | xUnit.net for .NET |
| `nunit-skill` | C# | NUnit for .NET |
| `mstest-skill` | C# | MSTest for .NET |
| `rspec-skill` | Ruby | RSpec with shared examples |
| `phpunit-skill` | PHP | PHPUnit with data providers |
| `testunit-skill` | Ruby | Test::Unit Ruby testing |
| `unittest-s
