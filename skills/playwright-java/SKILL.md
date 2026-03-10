---
name: playwright-java
description: Scaffold, write, debug, and enhance enterprise-grade Playwright E2E tests in Java using Page Object Model, JUnit 5, Allure reporting, and parallel execution. 
category: Creative & Media
source: antigravity
tags: [api, claude, ai, agent, automation, template, docker, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/playwright-java
---


# Playwright Java – Advanced Test Automation

## Overview

This skill produces production-quality, enterprise-grade Playwright Java test code.
It enforces the Page Object Model (POM), strict locator strategies, thread-safe parallel
execution, and full Allure reporting integration. Targets Java 17+ and Playwright 1.44+.

Supporting reference files are available for deeper topics:

| Topic | File |
|-------|------|
| Maven POM, ConfigReader, Docker/CI setup | `references/config.md` |
| Component pattern, dropdowns, uploads, waits | `references/page-objects.md` |
| Full assertion API, soft assertions, visual testing | `references/assertions.md` |
| Fixtures, test data factory, auth state, retry | `references/fixtures.md` |
| Drop-in base class templates | `templates/BaseTest.java`, `templates/BasePage.java` |

---

## When to Use This Skill

- Use when scaffolding a new Playwright Java project from scratch
- Use when writing Page Object classes or JUnit 5 test classes
- Use when the user asks about cross-browser testing, parallel execution, or Allure reports
- Use when fixing flaky tests or replacing `Thread.sleep()` with proper waits
- Use when setting up Playwright in CI/CD pipelines (GitHub Actions, Jenkins, Docker)
- Use when combining API calls and UI assertions in a single test (hybrid testing)
- Use when the user mentions "POM pattern", "BrowserContext", "Playwright fixtures", or "traces"

---

## How It Works

### Step 1: Decide the Approach

Use this matrix to pick the right pattern before writing any code:

| User Request | Approach |
|---|---|
| New project from scratch | Full scaffold — see `references/config.md` |
| Single feature test | POM page class + JUnit5 test class |
| API + UI hybrid | `APIRequestContext` alongside `Page` |
| Cross-browser | `@MethodSource` parameterized over browser names |
| Flaky test fix | Replace `sleep` with `waitFor` / `waitForResponse` |
| CI integration | `playwright install --with-deps` in pipeline |
| Parallel execution | `junit-platform.properties` + `ThreadLocal` |
| Rich reporting | Allure + Playwright trace + video recording |

---

### Step 2: Scaffold the Project Structure

Always use this layout when creating a new project:

```
src/
├── test/
│   ├── java/com/company/tests/
│   │   ├── base/
│   │   │   ├── BaseTest.java        ← templates/BaseTest.java
│   │   │   └── BasePage.java        ← templates/BasePage.java
│   │   ├── pages/
│   │   │   └── LoginPage.java
│   │   ├── tests/
│   │   │   └── LoginTest.java
│   │   ├── utils/
│   │   │   ├── TestDataFactory.java
│   │   │   └── WaitUtils.java
│   │   └── config/
│   │       └── ConfigReader.java
│   └── resources/
│       ├── test.properties
│       ├── junit-platform.properties
│       └── testdata/users.json
pom.xml
```

---

### Step 3: Set Up Thread-Safe BaseTest

```java
public class BaseTest {
    protected static ThreadLocal<Playwright>     playwrightTL = new ThreadLocal<>();
    protected static ThreadLocal<Browser>        browserTL    = new ThreadLocal<>();
    protected static ThreadLocal<BrowserContext> contextTL    = new ThreadLocal<>();
    protected static ThreadLocal<Page>           pageTL       = new ThreadLocal<>();

    protected Page page() { return pageTL.get(); }

    @BeforeEach
    void setUp() {
        Playwright playwright = Playwright.create();
        playwrightTL.set(playwright);

        Browser browser = resolveBrowser(playwright).launch(
            new BrowserType.LaunchOptions()
                .setHeadless(ConfigReader.isHeadless()));
        browserTL.set(browser);

        BrowserContext context = browser.newContext(new Browser.NewContextOptions()
            .setViewportSize(1920, 1080)
            .setRecordVideoDir(Paths.get("target/videos/"))
            .setLocale("en-US"));
        context.tracing().start(new Tracing.StartOptions()
            .setScreenshots(true).setSnapshots(true));
        contextTL.set(context);
        pageTL.set(context.newPage());
    }

    @AfterEach
    void tearDown(TestInfo testInfo) {
        String name = testInfo.getDisplayName().replaceAll("[^a-zA-Z0-9]", "_");
        contextTL.get().tracing().stop(new Tracing.StopOptions()
            .setPath(Paths.get("target/traces/" + name + ".zip")));
        pageTL.get().close();
        contextTL.get().close();
        browserTL.get().close();
        playwrightTL.get().close();
    }

    private BrowserType resolveBrowser(Playwright pw) {
        return switch (System.getProperty("browser", "chromium").toLowerCase()) {
            case "firefox" -> pw.firefox();
            case "webkit"  -> pw.webkit();
            default        -> pw.chromium();
        };
    }
}
```

---

### Step 4: Build Page Object Classes

```java
public class LoginPage extends BasePage {

    // Declare ALL locators as fields — never inline in action methods
    private final Locator emailInput;
    private final Locator passwordInput;
    private final Locator loginButton;
    private final Locator e
