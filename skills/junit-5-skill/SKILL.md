---
name: junit-5-skill
description: Generates production-grade JUnit 5 unit and integration tests in Java. Covers assertions, parameterized tests, lifecycle hooks, mocking with Mockito, and nested tests. Use when user mentions "JUnit", 
category: Development & Code Tools
source: antigravity
tags: [api, ai, agent, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/junit-5-skill
---


# JUnit 5 Testing Skill
## When to Use

Use this skill when you need generates production-grade JUnit 5 unit and integration tests in Java. Covers assertions, parameterized tests, lifecycle hooks, mocking with Mockito, and nested tests. Use when user mentions "JUnit", "JUnit 5", "@Test", "assertEquals", "Assertions", "Java unit test". Triggers on:...


You are a senior Java developer specializing in JUnit 5 testing.

## Step 1 — Test Type

```
├─ "unit test", "assert" → Standard unit test
├─ "parameterized", "multiple inputs" → @ParameterizedTest
├─ "mock", "Mockito" → Unit test with Mockito
├─ "integration test", "Spring" → Read reference/spring-integration.md
└─ Default → Standard unit test
```

## Core Patterns

### Basic Test

```java
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class CalculatorTest {
    private Calculator calculator;

    @BeforeEach
    void setUp() {
        calculator = new Calculator();
    }

    @Test
    @DisplayName("Addition of two positive numbers")
    void addPositiveNumbers() {
        assertEquals(5, calculator.add(2, 3));
    }

    @Test
    void divideByZero_throwsException() {
        assertThrows(ArithmeticException.class, () -> calculator.divide(10, 0));
    }

    @Test
    void multipleAssertions() {
        assertAll("calculator operations",
            () -> assertEquals(4, calculator.add(2, 2)),
            () -> assertEquals(0, calculator.subtract(2, 2)),
            () -> assertEquals(6, calculator.multiply(2, 3))
        );
    }
}
```

### Assertions Reference

```java
assertEquals(expected, actual);
assertNotEquals(unexpected, actual);
assertTrue(condition);
assertFalse(condition);
assertNull(object);
assertNotNull(object);
assertThrows(IllegalArgumentException.class, () -> service.process(null));
assertTimeout(Duration.ofSeconds(2), () -> service.longRunningOp());
assertAll("group",
    () -> assertNotNull(user.getName()),
    () -> assertTrue(user.getAge() > 0)
);
assertIterableEquals(List.of(1, 2, 3), actualList);
```

### Parameterized Tests

```java
@ParameterizedTest
@ValueSource(strings = {"hello", "world", "junit"})
void stringIsNotEmpty(String value) {
    assertFalse(value.isEmpty());
}

@ParameterizedTest
@CsvSource({"1,1,2", "2,3,5", "10,-5,5"})
void addNumbers(int a, int b, int expected) {
    assertEquals(expected, calculator.add(a, b));
}

@ParameterizedTest
@MethodSource("provideUsers")
void validateUser(String name, int age, boolean expected) {
    assertEquals(expected, validator.isValid(name, age));
}

static Stream<Arguments> provideUsers() {
    return Stream.of(
        Arguments.of("Alice", 25, true),
        Arguments.of("", 25, false),
        Arguments.of("Bob", -1, false)
    );
}

@ParameterizedTest
@NullAndEmptySource
@ValueSource(strings = {"  ", "\t"})
void blankStringsAreInvalid(String input) {
    assertFalse(validator.isValid(input));
}
```

### Mocking with Mockito

```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    @Mock private UserRepository userRepo;
    @Mock private EmailService emailService;
    @InjectMocks private UserService userService;

    @Test
    void createUser_savesAndSendsEmail() {
        User user = new User("alice@test.com", "Alice");
        when(userRepo.save(any(User.class))).thenReturn(user);

        User result = userService.createUser("alice@test.com", "Alice");

        assertNotNull(result);
        verify(userRepo).save(any(User.class));
        verify(emailService).sendWelcomeEmail("alice@test.com");
    }

    @Test
    void getUser_notFound_throwsException() {
        when(userRepo.findById(99L)).thenReturn(Optional.empty());
        assertThrows(UserNotFoundException.class, () -> userService.getUser(99L));
    }
}
```

### Nested Tests

```java
@DisplayName("UserService")
class UserServiceTest {
    @Nested
    @DisplayName("when creating a user")
    class CreateUser {
        @Test void withValidData_succeeds() { }
        @Test void withDuplicateEmail_throwsException() { }
    }

    @Nested
    @DisplayName("when deleting a user")
    class DeleteUser {
        @Test void existingUser_removesFromDb() { }
        @Test void nonExistentUser_throwsException() { }
    }
}
```

### Anti-Patterns

| Bad | Good | Why |
|-----|------|-----|
| `@Test public void test1()` | `@Test void shouldCalculateSum()` | Descriptive names |
| Testing private methods | Test via public API | Implementation detail |
| No @DisplayName | Always add display names | Better reporting |
| `assertEquals(true, x)` | `assertTrue(x)` | More readable |

## Maven Dependencies

```xml
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.11.0</version>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.mockito</groupId>
    <artifactId>mockito-junit-jupiter</artifactId>
    <version>5.14.0</version>
    <scope>test</scope>
</dependency>
```

## Quick Reference

| Task | Command |
|-----
