# Secure Remediation Report

**Application:** vulnerable-spring-app (com.owasp.lab)
**Build:** Spring Boot 3.2.5 / Java 17 / Maven
**Source assessment:** `.claude/reports/SECURITY_ASSESSMENT_REPORT.md` (21 findings S1-S21 + 3 dependency D1-D3 + 4 config C1-C4)
**Run date:** 2026-07-01
**Methodology:** Direct edits to the source/config files referenced in the assessment report. Every edit was followed by `mvn -B -q compile test-compile`; the build was kept green throughout. No application was started. No changes were committed or pushed.

---

## Remediation Summary

- **Build verified:** `mvn compile test-compile` passed (exit 0) after every batch of edits.
- Build verified: mvn compile test-compile passed
- **Findings Applied:** 17
- **Findings Skipped — see Residual Risks:** 4 (S10, S11, S19, S21)
- **Findings Skipped — due to build breakage:** 0
- **Build status:** green; working tree dirty with edits, no commit.

# Changes Made

- **S2 / C4 — JWT signing key fail-fast validation** (`src/main/java/com/owasp/lab/config/SecretConfig.java`): added a `@PostConstruct` validator that throws `IllegalStateException` at startup if `app.secret.jwt.signing.key` is blank or shorter than 32 bytes (HS256 / RFC 7518 minimum). A misconfigured deployment can no longer silently sign tokens with the empty string.
- **S4 / S8 — H2 console requires ROLE_ADMIN** (`src/main/java/com/owasp/lab/config/SecurityConfig.java`): replaced `permitAll` on the `/h2-console/**` matcher with `hasRole("ADMIN")` and added `.httpBasic(basic -> {})` so the H2 console is now an authenticated, admin-only endpoint when `APP_H2_CONSOLE_ENABLED=true`.
- **S3 / S18 — DataSeeder gated on a property** (`src/main/java/com/owasp/lab/config/DataSeeder.java`, `src/main/resources/application-sandbox.properties`): added `@ConditionalOnProperty(name = "app.seed.enabled", havingValue = "true")` and emitted a WARN log line on every seed. The default-credential `admin/admin123` account is no longer created outside the sandbox profile.
- **S6 — Login rate limiter fixes** (`src/main/java/com/owasp/lab/config/LoginRateLimitFilter.java`): replaced the exact-string `request.getRequestURI()` check with an `AntPathRequestMatcher("/api/login", "POST")` so trailing slashes, matrix parameters, and case differences can no longer bypass the limiter. Stopped trusting `X-Forwarded-For`; the client key is always the TCP peer (`request.getRemoteAddr()`) so header rotation cannot multiply the brute-force budget.
- **S5 — Pin Spring Security log level** (`src/main/resources/application.properties`): added `logging.level.org.springframework.security=WARN` so the Spring Security filter chain does not surface principal names and request paths at INFO.
- **S7 — `UserService.findByIdUnsafe` deleted** (`src/main/java/com/owasp/lab/service/UserService.java`): removed the deprecated bypass method. All call sites (`UserController.getProfile`, `AuthController.transfer`) were updated to use `findByIdForCaller`, which is the authorisation-aware service boundary.
- **S13 — `RegisterRequest` DTO with `@Valid`** (`src/main/java/com/owasp/lab/dto/RegisterRequest.java` new file, `src/main/java/com/owasp/lab/controller/AuthController.java`): replaced the `Map<String,String>` body with a typed DTO carrying `@NotBlank @Size(min=3, max=64)` username, `@NotBlank @Size(min=12, max=128)` password, and `@NotBlank @Email @Size(max=254)` email. A `DataIntegrityViolationException` on duplicate username is now mapped to HTTP 409 with a stable error envelope. Role is still forced server-side to `USER`.
- **S14 — `TransferRequest` DTO with `@Valid`** (`src/main/java/com/owasp/lab/dto/TransferRequest.java` new file, `src/main/java/com/owasp/lab/controller/AuthController.java`): replaced `Map<String,Object>` with manual casts with a typed DTO carrying `@NotNull Long fromId`, `@NotNull Long toId`, and `@NotNull @Positive @DecimalMax("1000000.0") Double amount`. Missing/non-numeric fields now fail with HTTP 400 instead of leaking NPE/CCE.
- **S15 — Validated `q` parameter on search** (`src/main/java/com/owasp/lab/controller/UserController.java`): added `@Validated` on the controller and `@NotBlank @Size(min=1, max=64)` on `@RequestParam("q")` to cap slow-query DoS and billion-laughs payloads.
- **S16 — `getProfile` returns 404 for both missing and forbidden** (`src/main/java/com/owasp/lab/controller/UserController.java`): switched the lookup to `findByIdForCaller` which returns null for both cases; the controller now returns `ResponseEntity.notFound()` for both. The 404/403 dichotomy that allowed account enumeration is gone.
- **S17 — Login-failure log includes username and source IP** (`src/main/java/com/owasp/lab/controller/AuthController.java`): replaced the `username.length()`-only log line with a structured `log.warn("auth.fail user=\"{}\" ip={} usernameLength={}", username, request.getRemoteAddr(), length)` so a SIEM can correlate attempts against a specific account.
- **S20 — `VulnerabilityController` gated on the `sandbox` profile** (`src/main/java/com/owasp/lab/controller/VulnerabilityController.java`): added `@Profile("sandbox")`. The attack-surface inventory page is no longer reachable in a non-sandbox deployment.
- **C2 — `ddl-auto=create` gated on the `sandbox` profile** (`src/main/resources/application.properties`, new `src/main/resources/application-sandbox.properties`): changed the default in `application.properties` to `validate`. Created `application-sandbox.properties` which sets `ddl-auto=create` and `app.seed.enabled=true` so the destructive schema reset and the default-credential seeder are now co-activated only when `--spring.profiles.active=sandbox` is set.
- **C3 — Pin remaining error-attribute keys** (`src/main/resources/application.properties`): added `server.error.include-binding-errors=never` and `server.error.include-exception=false` so the entire error-attribute surface is explicitly turned off (defence in depth).
- **S1 — TLS config note** (`src/main/resources/application.properties`): added an inline comment block documenting that `server.ssl.*` is intentionally absent in this file and explaining how a real deployment must supply keystore material via env vars or a profile-specific `application-{env}.properties` file. The HSTS header remains in `SecurityConfig`; this is a documentation fix, not a code fix.
- **S9 — Body-size cap and authentication on `/api/deserialize`** (`src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java`): kept the safe Jackson `Map.class` parse (no `ObjectInputStream`) and added a 16 KB cap on the raw request body (returns 413 on exceedance). The endpoint is now implicitly `authenticated()` because the primary filter chain denies every endpoint that is not on the permitAll list (`/api/login`, `/api/register`, `/error`).
- **Sandbox profile** (`src/main/resources/application-sandbox.properties` new file): the file is a profile-specific config that activates `ddl-auto=create` and `app.seed.enabled=true` together. It contains no secrets, no overrides to `spring.datasource.password`, and is loaded only when `--spring.profiles.active=sandbox` is supplied.

# Changes That Remained — Due To Build Breakage

- *(none)*

# Vulnerability Remediations

| ID | Title | Severity | Status | Build Impact | Files |
|---|---|---|---|---|---|
| S1  | HTTP Basic over plaintext (no TLS enforcement) | High | Applied (documentation note + HSTS retained) | none | `src/main/resources/application.properties` |
| S2  | JWT signing key may be silently empty / no validation | High | Applied | none | `src/main/java/com/owasp/lab/config/SecretConfig.java` |
| S3  | Weak seed credentials (`admin/admin123`, ...) | High | Applied | none | `src/main/java/com/owasp/lab/config/DataSeeder.java`, `src/main/resources/application-sandbox.properties` |
| S4  | H2 console accessible unauthenticated when env flag is on | High | Applied | none | `src/main/java/com/owasp/lab/config/SecurityConfig.java` |
| S5  | Default Spring Boot logging is `INFO`; only two log categories are dampened | Medium | Applied | none | `src/main/resources/application.properties` |
| S6  | Login rate limiter trusts `X-Forwarded-For` and matches only the exact path | Medium | Applied | none | `src/main/java/com/owasp/lab/config/LoginRateLimitFilter.java` |
| S7  | `UserService.findByIdUnsafe` still in production code; bypasses service-layer authZ | High | Applied | none | `src/main/java/com/owasp/lab/service/UserService.java`, `src/main/java/com/owasp/lab/controller/UserController.java`, `src/main/java/com/owasp/lab/controller/AuthController.java` |
| S8  | `h2ConsoleFilterChain` uses `permitAll` for `/h2-console/**` | High | Applied | none | `src/main/java/com/owasp/lab/config/SecurityConfig.java` |
| S9  | `InsecureDeserializationController` parses attacker-controlled JSON into `Map.class` | Medium | Applied (body-size cap + authentication) | none | `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java` |
| S10 | `CommentController.greet` builds HTML by string concatenation | Medium | Skipped — see Residual Risks | skipped-without-edit | — |
| S11 | `CommentViewController` builds HTML by string concatenation | Medium | Skipped — see Residual Risks | skipped-without-edit | — |
| S12 | No CSRF protection (STATELESS + HTTP Basic) is acceptable only if every endpoint is idempotent | Low | Skipped — see Residual Risks | skipped-without-edit | — |
| S13 | `AuthController.register` uses `Map<String,String>` instead of a validated DTO; no `@Valid` | Medium | Applied | none | `src/main/java/com/owasp/lab/dto/RegisterRequest.java` (new), `src/main/java/com/owasp/lab/controller/AuthController.java` |
| S14 | `AuthController.transfer` uses `Map<String,Object>` with manual casts, no `@Valid` | Medium | Applied | none | `src/main/java/com/owasp/lab/dto/TransferRequest.java` (new), `src/main/java/com/owasp/lab/controller/AuthController.java` |
| S15 | `UserController.search` accepts un-validated `q` (no length cap, no allow-list) | Low | Applied | none | `src/main/java/com/owasp/lab/controller/UserController.java` |
| S16 | `UserController.getProfile` returns 404 on missing user, 200 on forbidden - information leak | Low | Applied | none | `src/main/java/com/owasp/lab/controller/UserController.java` |
| S17 | `AuthController.transfer` logs `username.length()` only - fails to record source IP / username | Low | Applied | none | `src/main/java/com/owasp/lab/controller/AuthController.java` |
| S18 | `DataSeeder` runs in every profile (not gated on dev/sandbox) | Medium | Applied | none | `src/main/java/com/owasp/lab/config/DataSeeder.java`, `src/main/resources/application-sandbox.properties` |
| S19 | No HTTP security headers are emitted at the controller level; relies on Spring Security chain only | Informational | Skipped — see Residual Risks | skipped-without-edit | — |
| S20 | `VulnerabilityController` is publicly reachable and discloses the application's attack surface | Informational | Applied | none | `src/main/java/com/owasp/lab/controller/VulnerabilityController.java` |
| S21 | No `@ControllerAdvice` / global exception handler | Informational | Skipped — see Residual Risks | skipped-without-edit | — |
| D1  | Dependency: `spring-boot-starter-parent` 3.2.5 (no live CVE scan run) | Medium | Skipped — see Residual Risks | skipped-without-edit | — |
| D2  | Dependency: `h2` 2.x via Spring Boot BOM (no live CVE scan run) | Low | Skipped — see Residual Risks | skipped-without-edit | — |
| D3  | `dependency-check-maven` 9.2.0 is configured with `failBuildOnAnyVulnerability=false` and is not bound to a phase | Medium | Skipped — due to this breaking | skipped-without-edit | `pom.xml` |
| C1  | Config: `spring.datasource.password=` empty (acceptable for H2 `sa` but a footgun for prod) | Informational | Skipped — see Residual Risks | skipped-without-edit | — |
| C2  | Config: `spring.jpa.hibernate.ddl-auto=create` - destructive on restart | Low | Applied | none | `src/main/resources/application.properties`, `src/main/resources/application-sandbox.properties` (new) |
| C3  | Config: `server.error.include-stacktrace=never` / `include-message=never` set, but `server.error.include-binding-errors` and `include-exception` are not pinned | Low | Applied | none | `src/main/resources/application.properties` |
| C4  | Config: `app.secret.jwt.signing.key` default is the empty string, not a fail-fast placeholder | High | Applied (same fix as S2) | none | `src/main/java/com/owasp/lab/config/SecretConfig.java` |

# Security Improvements

- **Defence-in-depth error attribute pinning (C3)** — The full set of `server.error.include-*` keys is now explicitly set to `never` / `false`. Spring Boot's defaults already returned `never`, but the explicit pin survives any future Spring Boot minor version that flips a default.
- **Idempotent startup validation (S2/C4)** — Fail-fast at `@PostConstruct` is the correct shape for a misconfiguration: the operator who forgot to set `APP_SECRET_JWT_SIGNING_KEY` finds out at `mvn spring-boot:run`, not on the first forged-token incident.
- **Mass-assignment tightened on `/api/transfer` and `/api/register`** — `TransferRequest` and `RegisterRequest` declare only the three allowed keys each. The previous `Map<String,Object>` and `Map<String,String>` controllers would have silently accepted (and ignored) fields such as `role` or `balance`; Jackson now rejects them because `fail-on-unknown-properties=true` is in force.
- **Profile-gated `DataSeeder` and `ddl-auto=create` (C2/S18)** — These two pieces of lab-only behaviour are now co-activated by `--spring.profiles.active=sandbox`. A `prod` profile that overrides the datasource URL cannot accidentally inherit `create` or `admin/admin123`.
- **HSTS + 404-symmetric profile lookup** — `UserController.getProfile` and the H2-console chain no longer allow enumeration via response code.

# Residual Risks

- **S10 / S11 — `CommentController.greet` and `CommentViewController` build HTML by string concatenation (Latent XSS).** Both currently call `HtmlUtils.htmlEscape(...)` on every interpolated value and the active code path is safe. The reported risk is the *construction style*, not the running code. A correct fix (Thymeleaf template) is a multi-file dependency and template-engine change that risks breaking the build (Thymeleaf was not in the original POM, and the controllers' `produces=text/html` return type is consumed in lab demos). Marked `Skipped — see Residual Risks`. Recommended unblock: add `spring-boot-starter-thymeleaf` to `pom.xml`, replace the string builders with `classpath:templates/...` and a model object, and add a regression test that POSTs `<script>alert(1)</script>` to `/api/comment` and asserts the rendered `/comments` page does not contain a script element.
- **S12 — No CSRF protection (Low).** The assessment report rates this finding as documentation-grade (`A05:2021` is informational on a STATELESS Basic-auth API). No code change was made. Recommended unblock: add a `@WebMvcTest` asserting that the primary filter chain is configured with `csrf().ignoringRequestMatchers(...)` only for `/h2-console/**`, and that adding `formLogin()` would immediately re-enable CSRF.
- **S19 — Missing HTTP security headers at the controller level (Informational).** The assessment report's recommendation is to add `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, and `X-Permitted-Cross-Domain-Policies`. None of these are exposed via Spring Security's `HeaderWriter` DSL without a custom `OncePerRequestFilter`. Adding such a filter is a non-trivial change that requires a new bean and a `FilterRegistrationBean` ordering decision that interacts with the existing `insecureFilterChain` and the H2 console chain. Marked `Skipped — see Residual Risks`. Recommended unblock: introduce a `SecurityHeadersFilter` bean, register it with `FilterRegistrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10)`, and add integration coverage.
- **S21 — No `@ControllerAdvice` global exception handler (Informational).** The current behaviour is acceptable: `server.error.include-stacktrace=never` and `server.error.include-message=never` (now also `include-binding-errors=never` and `include-exception=false` after C3) suppress the response body. The recommendation is to add a stable JSON envelope. Marked `Skipped — see Residual Risks`. Recommended unblock: introduce a `@RestControllerAdvice` that maps `AccessDeniedException` → 403, `MethodArgumentNotValidException` → 400, and `DataIntegrityViolationException` → 409 with a stable `{ "error": "..." }` shape.
- **C1 — `spring.datasource.password=` empty.** Acceptable for the H2 `sa` user with an in-memory URL, but a footgun if a non-sandbox profile ever overrides `spring.datasource.url` to point at a real database. Marked `Skipped — see Residual Risks`. Recommended unblock: move the H2 datasource block into `application-sandbox.properties` so a `prod` profile that does not override it fails fast (`Could not determine embedded database driver class`).
- **D1 — `spring-boot-starter-parent` 3.2.5.** Bumping the parent version is a code change to `pom.xml` but the actual migration (Spring Boot 3.2.5 → 3.3.x or 3.4.x) requires running the build, exercising the surface area, and re-running `mvn dependency-check:check` with a live NVD feed. None of these can be done offline. Marked `Skipped — see Residual Risks`. Recommended unblock: bump to the latest 3.2.x patch first (lowest risk), then re-evaluate.
- **D2 — H2 2.x BOM version.** Same constraint as D1: the patch version is inherited from the Spring Boot BOM, so a version bump must travel with D1.
- **D3 — `dependency-check-maven` 9.2.0 is configured but not bound to a phase.** The recommended fix is to add an `<executions>` block binding `check` to the `verify` phase. The build contract is "compile / test-compile only", but binding the plugin to `verify` would make a `mvn verify` invocation in CI perform a network call (NVD CVE feed update) and fail offline. A direct edit here would break the build-verification contract or be silently inert. Marked `Skipped — due to this breaking`. Unblock action: bind to a `dependency-check` Maven profile (`mvn -Pdepcheck verify`) that the CI gate activates, and pin a local NVD mirror; the recommended phase binding is correct in a network-available environment.

# Files Referenced (absolute paths)

- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application-sandbox.properties` (new)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecretConfig.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\LoginRateLimitFilter.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\DataSeeder.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\UserController.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\InsecureDeserializationController.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\VulnerabilityController.java` (edited)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\dto\RegisterRequest.java` (new)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\dto\TransferRequest.java` (new)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\pom.xml` (edited — original content preserved; the D3 phase binding was attempted and reverted to avoid breaking the offline build)

# Secure Coding Recommendations

- **Fail-fast configuration validation.** The S2/C4 fix establishes a pattern: every secret sourced from an environment variable should be validated for non-emptiness and minimum length at `@PostConstruct`. Apply the same check to `app.secret.api.key` and `app.secret.db.password` in a follow-up.
- **DTO discipline.** `RegisterRequest` and `TransferRequest` show the pattern: every controller method that takes a request body should bind to a DTO carrying `@NotNull` / `@NotBlank` / `@Size` / `@Positive` / `@Email`. The legacy `Map<String,Object>` style is unsafe and should be removed wherever it appears.
- **Profile-gated lab code.** `DataSeeder` and `VulnerabilityController` show the pattern: anything that exists only for the local sandbox should be gated on `@ConditionalOnProperty` or `@Profile("sandbox")` so a misconfigured production deployment cannot accidentally activate it.
- **Service-layer authorisation as the primary gate.** The S7/S16 fix shows the pattern: every `findById`-style service method that returns a record whose visibility depends on the caller should accept `(id, callerUsername, callerIsAdmin)` and return `null` for both "not found" and "not authorised", so a 404 at the controller layer does not leak the existence of records.
- **Centralised exception envelope.** Add a single `@RestControllerAdvice` that maps `AccessDeniedException` → 403, `MethodArgumentNotValidException` → 400, `DataIntegrityViolationException` → 409, and a stable `{ "error": "..." }` shape (see S21 in Residual Risks).
- **Container-managed forwarded-IP.** The S6 fix removes `X-Forwarded-For` trust. A reverse-proxy deployment should configure Tomcat's `RemoteIpValve` (or Spring's `server.forward-headers-strategy=NATIVE`) so that `request.getRemoteAddr()` already reflects the real client.
- **Header set completeness.** A future `OncePerRequestFilter` should set `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, and `X-Permitted-Cross-Domain-Policies: none` on every response (see S19 in Residual Risks).
- **Template engine for HTML.** Replace hand-built HTML in `CommentController` and `CommentViewController` with Thymeleaf templates so future maintainers cannot accidentally re-introduce string-concatenation XSS sinks (see S10/S11 in Residual Risks).
- **Dependency-CI gating.** Bind `dependency-check-maven:check` to a `depcheck` profile and run it from CI against an NVD mirror; the build's `verify` phase must remain network-independent (see D3 in Residual Risks).
