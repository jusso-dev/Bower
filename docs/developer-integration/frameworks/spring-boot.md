# Spring Boot

Uses [`BowerEvents.java`](../../../examples/asvs-logging/java/src/main/java/example/bower/BowerEvents.java),
which needs only the JDK (17 and later), plus four Spring components. Read the
[shared guidance](../asvs-logging-frameworks.md) first.

## Components

| Class | What it does |
|---|---|
| [`BowerRequestFilter`](../../../examples/asvs-logging/java/src/main/java/example/bower/spring/BowerRequestFilter.java) | Highest-precedence filter: request ID (from `traceparent` or a UUID) in a request attribute, the `X-Request-Id` header and the logging MDC; trusted client IP |
| [`BowerSecurity`](../../../examples/asvs-logging/java/src/main/java/example/bower/spring/BowerSecurity.java) | `emit(spec)`: adds the current request's context (route pattern from `BEST_MATCHING_PATTERN_ATTRIBUTE`) and sends asynchronously |
| [`BowerAuthenticationEvents`](../../../examples/asvs-logging/java/src/main/java/example/bower/spring/BowerAuthenticationEvents.java) | Spring Security `AuthenticationSuccessEvent`, failure events, `LogoutSuccessEvent` and `AuthorizationDeniedEvent` |
| [`BowerErrorHandler`](../../../examples/asvs-logging/java/src/main/java/example/bower/spring/BowerErrorHandler.java) | `@RestControllerAdvice` for validation failures and a last-resort handler with a generic body |

Spring Boot publishes authentication events through its default
`AuthenticationEventPublisher`. For `AuthorizationDeniedEvent`, declare an
`AuthorizationEventPublisher` bean (`SpringAuthorizationEventPublisher`).

## Configuration

[`application.properties`](../../../examples/asvs-logging/java/src/main/resources/application.properties):

- `server.forward-headers-strategy=none`: the filter applies `TRUSTED_PROXIES`; don't let
  Tomcat rewrite the peer address as well.
- `logging.structured.format.console=ecs`: JSON application logs (Spring Boot 3.4 and later).
- `server.error.include-stacktrace=never` and `include-message=never` (ASVS 5.0 V16.5.1).

The failure listener never calls `getCredentials()`, which holds the submitted password.

## What was run

`BowerEvents.java` was compiled with JDK 17 and matches the cross-language contract. The
four Spring classes were compiled against spring-web, spring-webmvc, spring-context and
spring-security-core jars (Spring Framework 6.2, Spring Security 6.5) with `javac`. A Spring
Boot application was **not** started, and the `pom.xml` was not built with Maven.
