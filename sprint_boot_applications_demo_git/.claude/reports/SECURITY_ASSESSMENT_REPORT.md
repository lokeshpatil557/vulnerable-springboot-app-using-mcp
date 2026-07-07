# Security Assessment Report

**Application:** vulnerable-spring-app (com.owasp.lab)
**Build:** Spring Boot 3.2.5 / Java 17 / Maven
**Assessment date:** 2026-06-30
**Methodology:** Read-only static review of source tree, application properties, Maven POM, and project metadata. No code was modified. No builds were run.
**Application type:** Intentional OWASP Top-10 learning lab (per the project header in `pom.xml` and the class doc of `VulnerableSpringAppApplication`).

> Note on posture: The application is **explicitly documented as intentionally insecure / sandbox-only** ("DO NOT deploy this to any public server", `pom.xml` lines 7-12). Every finding below is therefore "still present at the time of this scan"; many of them are listed in the lab's own remediation comments. They are nonetheless re-issued here as raw findings with the same rigor as a real engagement, because the agents downstream of this report (remediation agent, build/CI gate) treat the output verbatim.

---

## 1. Executive Summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High     | 6 |
| Medium   | 6 |
| Low      | 4 |
| Informational | 3 |
| **Total** | **21** |

**Overall risk posture: HIGH (in its current form).** The application is *remediated against the historical lab flaws* (no `permitAll` blanket, no plaintext passwords, no string-concatenated SQL, no `ObjectInputStream`, no hardcoded `app.secret.*` literals) but it still ships with the following live issues that would be unacceptable in any non-sandbox deployment:

- HTTP Basic auth without TLS enforcement (S1).
- JWT signing key may be silently empty at runtime (S2).
- Verbose error / SQL logging still on by Spring Boot defaults outside the two explicitly-muted categories (S5).
- H2 console can be turned on with a single env var; the permitting `SecurityFilterChain` then grants **fully unauthenticated** access to `/h2-console/**` (S4 / S8).
- `LoginRateLimitFilter` only triggers on the **exact** path `/api/login` and trusts `X-Forwarded-For` from any caller (S6).
- `Cache-Control: no-store` is set on success, but the static `/vulnerabilities` page still serves an unauthenticated inventory of attack surface and references "INTENTIONALLY INSECURE" metadata (I1).
- Spring Boot 3.2.5 + dependency-check plugin 9.2.0 are recent enough to be supported but no `mvn dependency-check:check` is wired into the build by default; CVEs are not gated (D1).
- The legacy service method `UserService.findByIdUnsafe` is retained and reachable from `AuthController.transfer`, providing a back-door bypass to the new authorisation check at the service layer (S7 / A01).

---

## 2. Scope & Methodology

### In scope (scanned)

- All Java sources under `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\**`
- `pom.xml` (root) and any sibling build descriptor
- `src/main/resources/application.properties` (only config in tree; no `application.yml` / `.yaml` exists)
- `.claude/agents/*.md` (read for the running contract only, not a target)
- `.github/workflows/build-and-security.yml` (referenced in pom.xml; not opened - *not scanned*)

### Out of scope (explicit)

- `src/test/**` - no test directory exists in the tree (Glob returned no matches for `**/test/**/*`).
- `target/**` (build output).
- Front-end assets (no `templates/`, no `static/`, no `*.html` source files in `src/`).
- YAML / SnakeYAML - no `.yml` / `.yaml` files exist anywhere in the repo.

### Tools and pattern sweeps used

- `Glob` to enumerate all `*.java`, `*.properties`, `*.xml`, `*.yml`, `*.yaml`, `*.html`, `*.jsp`, `**/test/**`, `**/templates/**`, `**/static/**`.
- `Grep` for the following risk tokens, with `output_mode=content` and line numbers, in `src/main/java` and `src/main/resources`:
  - `Runtime\.exec|ProcessBuilder|System\.getenv|System\.getproperty|ObjectInputStream|readObject|XStream|SnakeYAML|new Yaml|@JsonTypeInfo|default typing|MessageDigest|getInstance`
  - `md5|MD5|sha1|SHA-1|DES|RC4|java\.util\.Random|SecureRandom|new Random|Cipher|KeyGenerator`
  - `password|secret|api[._-]?key|token|credentials|jwt`
  - `log\.|logger\.|LoggerFactory|slf4j`
  - `new File|Paths\.get|getCanonicalPath|transferTo|FileOutputStream|Files\.write|multipart|@RequestPart`
  - `actuator|management\.`
  - `createQuery|createNativeQuery|@Query|EntityManager|JdbcTemplate`
  - `TODO|FIXME|HACK|XXX|SECURITY|BUG`
  - `URL|URI|openConnection|HttpURLConnection|RestTemplate|WebClient|HttpClient|redirect|sendRedirect`
  - `permitAll|hasRole|hasAuthority|@PreAuthorize|@Secured|@RolesAllowed|@EnableMethodSecurity|WebSecurityConfigurerAdapter|authorizeHttpRequests|anyRequest|csrf|STATELESS|httpBasic|cors`
  - `EmailValidator|@Email|@Valid|@Validated|@RequestParam|@PathVariable|@RequestBody`
- `Read` on every file that produced a match or that is security-relevant (`SecurityConfig`, `PasswordConfig`, `SecretConfig`, `LoginRateLimitFilter`, `DataSeeder`, `JpaUserDetailsService`, every controller, both DTOs, every entity, both services, both repositories, `VulnerableSpringAppApplication`, `pom.xml`, `application.properties`).

### Caveats

- **No build was run.** `mvn dependency-check:check` and SCA were not executed. Dependency findings are based on declared versions, not on a CVE database lookup. (CVE cross-referencing requires a live feed.)
- **No dynamic testing was performed.** All findings are static.
- The lab banner (`OWASP VULNERABILITY LEARNING LAB`, "INTENTIONALLY INSECURE", "DO NOT DEPLOY") is reproduced verbatim from `pom.xml` lines 7-12 and `application.properties` lines 1-5. We do **not** soften any finding because of that banner - the task contract is a security assessment, and the parent pipeline (push gates) consumes the findings verbatim.

---

## 3. Findings

> Remediation status for every finding below: **Not Applied** (this run is assessment-only). Several items map to VULN-NNN identifiers in the project's own remediation comments; the report preserves those cross-references for traceability.

| ID | Title | Severity | OWASP 2021 | CWE |
|---|---|---|---|---|
| S1  | HTTP Basic over plaintext (no TLS enforcement) | High | A02 Cryptographic Failures | CWE-319 |
| S2  | JWT signing key may be silently empty / no validation | High | A02 Cryptographic Failures | CWE-321 |
| S3  | Weak seed credentials (`admin/admin123`, `alice/alice123`, `bob/bob123`) | High | A07 Identification & Auth Failures | CWE-521 |
| S4  | H2 console accessible unauthenticated when env flag is on | High | A05 Security Misconfiguration | CWE-306 |
| S5  | Default Spring Boot logging is `INFO`; only two log categories are dampened | Medium | A09 Security Logging & Monitoring Failures | CWE-532 |
| S6  | Login rate limiter trusts `X-Forwarded-For` and matches only the exact path | Medium | A04 Insecure Design | CWE-348 |
| S7  | `UserService.findByIdUnsafe` still in production code; bypasses service-layer authZ | High | A01 Broken Access Control | CWE-639 |
| S8  | `h2ConsoleFilterChain` uses `permitAll` for `/h2-console/**` | High | A05 Security Misconfiguration | CWE-1188 |
| S9  | `InsecureDeserializationController` parses attacker-controlled JSON into `Map.class` | Medium | A08 Software & Data Integrity Failures | CWE-502 |
| S10 | `CommentController.greet` builds HTML by string concatenation | Medium | A03 Injection (XSS) | CWE-79 |
| S11 | `CommentViewController` builds HTML by string concatenation | Medium | A03 Injection (XSS) | CWE-79 |
| S12 | No CSRF protection (STATELESS + HTTP Basic) is acceptable only if every endpoint is idempotent | Low | A05 Security Misconfiguration | CWE-352 |
| S13 | `AuthController.register` uses `Map<String,String>` instead of a validated DTO; no `@Valid` | Medium | A04 Insecure Design | CWE-20 |
| S14 | `AuthController.transfer` uses `Map<String,Object>` with manual casts, no `@Valid` | Medium | A04 Insecure Design | CWE-20 |
| S15 | `UserController.search` accepts un-validated `q` (no length cap, no allow-list) | Low | A04 Insecure Design | CWE-20 |
| S16 | `UserController.getProfile` returns 404 on missing user, 200 on forbidden - information leak | Low | A01 Broken Access Control | CWE-200 |
| S17 | `AuthController.transfer` logs `username.length()` only - fails to record source IP / username | Low | A09 Security Logging & Monitoring Failures | CWE-778 |
| S18 | `DataSeeder` runs in every profile (not gated on dev/sandbox) | Medium | A05 Security Misconfiguration | CWE-1188 |
| S19 | No HTTP security headers are emitted at the controller level; relies on Spring Security chain only | Informational | A05 Security Misconfiguration | CWE-693 |
| S20 | `VulnerabilityController` is publicly reachable and discloses the application's attack surface | Informational | A05 Security Misconfiguration | CWE-200 |
| S21 | No `@ControllerAdvice` / global exception handler - `AccessDeniedException` is allowed to bubble to default error path | Informational | A09 Security Logging & Monitoring Failures | CWE-209 |
| D1  | Dependency: `spring-boot-starter-parent` 3.2.5 (no live CVE scan run) | Medium | A06 Vulnerable & Outdated Components | CWE-1104 |
| D2  | Dependency: `h2` 2.x via Spring Boot BOM (no live CVE scan run) | Low | A06 Vulnerable & Outdated Components | CWE-1104 |
| D3  | `dependency-check-maven` 9.2.0 is configured with `failBuildOnAnyVulnerability=false` and is not bound to a phase | Medium | A06 Vulnerable & Outdated Components | CWE-1104 |
| C1  | Config: `spring.datasource.password=` empty (acceptable for H2 `sa` but a footgun for prod) | Informational | A05 Security Misconfiguration | CWE-1188 |
| C2  | Config: `spring.jpa.hibernate.ddl-auto=create` - destructive on restart | Low | A05 Security Misconfiguration | CWE-1188 |
| C3  | Config: `server.error.include-stacktrace=never` / `include-message=never` set, but `server.error.include-binding-errors` and `include-exception` are not pinned | Low | A05 Security Misconfiguration | CWE-209 |
| C4  | Config: `app.secret.jwt.signing.key` default is the empty string, not a fail-fast placeholder | High | A02 Cryptographic Failures | CWE-321 |

(Note: S2 and C4 are facets of the same root cause. They are listed separately so the report's table of contents is exhaustive; they are deduplicated in the priority roadmap.)

---

### S1 - HTTP Basic over plaintext (no TLS enforcement)

- **Severity:** High
- **CWE:** CWE-319 Cleartext Transmission of Sensitive Information
- **OWASP Top 10 (2021):** A02 Cryptographic Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Method / Class:** `insecureFilterChain(HttpSecurity)`
- **Evidence (lines 52-56):**
  ```java
  // REMEDIATION (A05:2021): enable HTTP Basic so the
  // AuthenticationManager (backed by the JPA user details
  // service) is exercised on every request, and the
  // @AuthenticationPrincipal injection on /api/transfer works.
  .httpBasic(basic -> {})
  ```
- **Root cause:** The lab authenticates with `HttpBasic` over `server.port=8080` (HTTP). `application.properties` does not configure `server.ssl.*` (no TLS keystore/truststore). The only TLS signal in the build is an HSTS header (set for 1 year) emitted in `SecurityConfig.java` lines 83-84, but HSTS only takes effect when the response is *first* received over HTTPS.
- **Exploitation scenario:** Any on-path attacker between the user and the server captures `Authorization: Basic ...` and replays it. The seed users (`alice`, `bob`, `admin`) are then trivially impersonated.
- **Business impact:** Total compromise of every authenticated account. The `/api/transfer` endpoint then permits fund movement from any captured `USER` account.
- **Recommended fix:** Terminate TLS at a reverse proxy (nginx / Spring Cloud Gateway / a managed LB) or configure `server.ssl.*` in `application.properties`. Disable the `httpBasic` chain and require a token-based scheme (`Authorization: Bearer ...`) or form login over HTTPS. Do not rely on the HSTS header alone.
- **Remediation status:** Not Applied

### S2 - JWT signing key may be silently empty

- **Severity:** High
- **CWE:** CWE-321 Use of a Hard-coded, Predictable, or Static Cryptographic Key
- **OWASP Top 10 (2021):** A02 Cryptographic Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecretConfig.java`
- **Method / Class:** `SecretConfig` (field `jwtSigningKey`)
- **Evidence (lines 30-34):**
  ```java
  @Value("${app.secret.jwt.signing.key:}")
  private String jwtSigningKey;
  ```
  and the placeholder in `application.properties` line 34:
  ```
  app.secret.jwt.signing.key=${APP_SECRET_JWT_SIGNING_KEY:}
  ```
- **Root cause:** The default value when the env var is unset is the empty string `""`. The bean is exposed under name `jwtSigningKey` and any future JWT issuer can pick it up without ever failing fast.
- **Exploitation scenario:** A future change that signs JWTs with `jwtSigningKey` will silently sign tokens with `""`, which is equivalent to a publicly-known signing secret. Anyone with knowledge of this default can forge tokens for `ROLE_ADMIN`.
- **Business impact:** Privilege escalation to admin via forged JWTs once a JWT-issuing endpoint is added.
- **Recommended fix:** Validate non-empty + minimum entropy at startup (`@PostConstruct` or `EnvironmentValidator`); throw a fail-fast `IllegalStateException` if `app.secret.jwt.signing.key` is blank or shorter than 32 bytes.
- **Remediation status:** Not Applied

### S3 - Weak seed credentials

- **Severity:** High
- **CWE:** CWE-521 Weak Password Requirements
- **OWASP Top 10 (2021):** A07 Identification & Authentication Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\DataSeeder.java`
- **Method / Class:** `seed(...)` `CommandLineRunner`
- **Evidence (lines 31-37):**
  ```java
  userRepository.save(new User("alice", passwordEncoder.encode("alice123"),
          "alice@example.com", "USER",  1000.0));
  userRepository.save(new User("bob",   passwordEncoder.encode("bob123"),
          "bob@example.com",   "USER",   500.0));
  userRepository.save(new User("admin", passwordEncoder.encode("admin123"),
          "admin@example.com", "ADMIN", 9999.0));
  ```
- **Root cause:** The seeder creates an `admin/admin123` account on **every** startup, not gated on a sandbox profile. The passwords are short, common, and guessable.
- **Exploitation scenario:** A default-credential login. `POST /api/login` with `{"username":"admin","password":"admin123"}` returns the admin record and the attacker now holds a `ROLE_ADMIN` token.
- **Business impact:** Full administrative compromise. With the existing `/api/users` and `/api/comment` (POST) and `/api/products` (POST) endpoints, the attacker can read every PII record and write admin content.
- **Recommended fix:** Gate the seeder on a Spring profile (`@Profile("sandbox")` or `@ConditionalOnProperty(name="app.seed.enabled", havingValue="true")`); require the seeder to refuse to run if `spring.profiles.active` includes `prod`. Print a loud startup warning that seed users are present.
- **Remediation status:** Not Applied (no `@Profile` guard; not even a startup log line).

### S4 / S8 - H2 console accessible unauthenticated when env flag is on

- **Severity:** High
- **CWE:** CWE-306 Missing Authentication for Critical Function / CWE-1188 Insecure Default Initialization
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **Files:**
  - `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
  - `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Method / Class:** `h2ConsoleFilterChain(HttpSecurity)` / `spring.h2.console.*`
- **Evidence (`SecurityConfig.java` lines 99-110):**
  ```java
  @Bean
  @Order(0)
  @ConditionalOnProperty(name = "app.h2.console.enabled", havingValue = "true")
  public SecurityFilterChain h2ConsoleFilterChain(HttpSecurity http) throws Exception {
      http
          .securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
          .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
          .csrf(csrf -> csrf.ignoringRequestMatchers(
                  new AntPathRequestMatcher("/h2-console/**")))
          .headers(h -> h.frameOptions(f -> f.sameOrigin()));
      return http.build();
  }
  ```
  and `application.properties` lines 26-28:
  ```
  app.h2.console.enabled=${APP_H2_CONSOLE_ENABLED:false}
  spring.h2.console.enabled=${APP_H2_CONSOLE_ENABLED:false}
  spring.h2.console.path=/h2-console
  ```
- **Root cause:** When an operator sets `APP_H2_CONSOLE_ENABLED=true`, the entire `/h2-console/**` tree becomes `permitAll` *and* CSRF is disabled *and* `frameOptions` is relaxed to `sameOrigin` (so the console can be iframed - historically required by H2). The default in H2 is `jdbc:h2:mem:owaspdb;DB_CLOSE_DELAY=-1` with user `sa` and **empty password** (lines 17-20). Anyone reaching the console can read and modify the user table.
- **Exploitation scenario:** Set `APP_H2_CONSOLE_ENABLED=true` (a single env var), navigate to `/h2-console`, log in with `sa` / empty password, and read `SELECT * FROM USERS` to harvest password hashes, or `UPDATE USERS SET role='ADMIN' WHERE username='attacker'`.
- **Business impact:** Mass credential harvest; silent privilege escalation by direct DB write.
- **Recommended fix:** Require a dedicated admin principal to reach the H2 console (Basic auth on a separate chain bound to a `/h2-console/**` matcher that requires `ROLE_ADMIN`). Force a non-empty JDBC password even for in-memory. Do not relax `frameOptions`. Better: do not ship H2 console in production builds at all (Maven profile + exclusion).
- **Remediation status:** Not Applied

### S5 - Default Spring Boot logging not pinned

- **Severity:** Medium
- **CWE:** CWE-532 Insertion of Sensitive Information into Log File
- **OWASP Top 10 (2021):** A09 Security Logging & Monitoring Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Evidence (lines 44-45):**
  ```
  logging.level.org.hibernate.SQL=WARN
  logging.level.org.hibernate.type.descriptor.sql=NONE
  ```
- **Root cause:** The application dampens only Hibernate SQL categories. Spring Security's own INFO logs are not raised, but neither are they raised to WARN/ERROR. By default, the Spring Boot parent sets `logging.level.root=INFO`, so `o.s.s.web` / `o.s.s.access` may log request paths, principal names, and authorities at INFO. Worse, the application does not configure a `logback-spring.xml` and does not pin a log file location, so the path is whatever the runtime decides.
- **Exploitation scenario:** After a successful brute force, the only signal is `Failed login attempt for username of length N` (`AuthController.java` lines 54-56). There is no log entry on successful logins, no entry on transfer, no entry on profile reads. An attacker who reaches the H2 console leaves no log trail in the application.
- **Business impact:** Lack of detectability. Brute force, account enumeration, and IDOR attempts are not observable.
- **Recommended fix:** Set `logging.level.org.springframework.security=INFO` (explicit), add structured logback with a file appender, emit a security-audit event for login success/failure, transfer, profile access, and admin actions. Consider AOP `@Aspect` around `@PreAuthorize` and `AuthenticationManager.authenticate`.
- **Remediation status:** Not Applied

### S6 - Login rate limiter trusts `X-Forwarded-For` and matches only exact path

- **Severity:** Medium
- **CWE:** CWE-348 Use of a Less Trusted Source / CWE-770 Allocation of Resources Without Limits or Throttling
- **OWASP Top 10 (2021):** A04 Insecure Design
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\LoginRateLimitFilter.java`
- **Method / Class:** `LoginRateLimitFilter.clientKey(HttpServletRequest)` / `doFilterInternal`
- **Evidence (lines 41-45, 73-80):**
  ```java
  if (!LOGIN_PATH.equals(request.getRequestURI())
          || !"POST".equalsIgnoreCase(request.getMethod())) {
      chain.doFilter(request, response);
      return;
  }
  String key = clientKey(request);
  ...
  private String clientKey(HttpServletRequest request) {
      String fwd = request.getHeader("X-Forwarded-For");
      if (fwd != null && !fwd.isBlank()) {
          int comma = fwd.indexOf(',');
          return (comma > 0 ? fwd.substring(0, comma) : fwd).trim();
      }
      return request.getRemoteAddr();
  }
  ```
- **Root cause:** Two issues, both findings: (a) the filter matches only `request.getRequestURI() == "/api/login"` - a trailing slash, a `;` matrix parameter, a different servlet mapping, or a case difference in the path bypasses the limiter entirely; (b) the limiter blindly trusts `X-Forwarded-For` from the *direct* TCP peer. An attacker can rotate the header (`X-Forwarded-For: 1.1.1.1`, then `2.2.2.2`, ...) to multiply their budget by 5x per IP.
- **Exploitation scenario:** Send 4 failed `POST /api/login` requests per spoofed `X-Forwarded-For` value, then rotate the header. Total failed attempts is unbounded; the brute-force window in `UserService.loginUnsafe` has no other backstop.
- **Business impact:** Defeats the only brute-force mitigation in the app.
- **Recommended fix:** (a) use `request.getServletPath()` and an `AntPathRequestMatcher`; (b) read `X-Forwarded-For` only when the connection came from a trusted reverse-proxy CIDR; (c) fall back to a Redis/Bucket4j-backed counter that survives restarts and is consistent across replicas.
- **Remediation status:** Not Applied

### S7 - `UserService.findByIdUnsafe` retained; bypasses service-layer authZ

- **Severity:** High
- **CWE:** CWE-639 Authorization Bypass Through User-Controlled Key
- **OWASP Top 10 (2021):** A01 Broken Access Control
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java`
- **Method / Class:** `findByIdUnsafe(Long)`
- **Evidence (lines 116-119):**
  ```java
  @Deprecated
  public User findByIdUnsafe(Long id) {
      return userRepository.findById(id).orElse(null);
  }
  ```
  Callers (line 100 in `AuthController.java`):
  ```java
  User from = userService.findByIdUnsafe(fromId);
  ```
- **Root cause:** The new `findByIdForCaller(...)` method is the safe, authorization-aware lookup, but `findByIdUnsafe` is kept around and still called from `AuthController.transfer` (line 100) and `UserController.getProfile` (line 57). The controller does its own ownership check, so the vulnerability is **defence-in-depth erosion**, not a primary flaw. A future caller (or a refactor that drops the controller check) immediately re-introduces IDOR.
- **Exploitation scenario:** A future code path calls `userService.findByIdUnsafe(otherId)` to look up a counter-party and returns the record without checking the principal.
- **Business impact:** IDOR re-emerges silently; no compile-time enforcement.
- **Recommended fix:** Delete `findByIdUnsafe`; route every call through `findByIdForCaller(id, principal, isAdmin)`. If retention is required, rename to `findByIdForAdminInternal` and `package-private` it so only the admin controller can call it.
- **Remediation status:** Not Applied (the deprecated method is still public and still called).

### S9 - `InsecureDeserializationController` parses attacker-controlled JSON into `Map.class`

- **Severity:** Medium
- **CWE:** CWE-502 Deserialization of Untrusted Data
- **OWASP Top 10 (2021):** A08 Software & Data Integrity Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\InsecureDeserializationController.java`
- **Method / Class:** `deserialize(String)`
- **Evidence (lines 37-47):**
  ```java
  @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
               produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
      // SAFE: parse as untyped JSON (Map). Never call readObject().
      @SuppressWarnings("unchecked")
      Map<String, Object> parsed = objectMapper.readValue(body, Map.class);
      return ResponseEntity.ok(Map.of(
              "type", "Map<String,Object>",
              "size", parsed == null ? 0 : parsed.size()
      ));
  }
  ```
- **Root cause:** The class was rewritten to use Jackson `Map.class` and not `ObjectInputStream`, but the global Jackson config (`application.properties` line 50) sets `spring.jackson.deserialization.fail-on-unknown-properties=true` - this only applies when the target type is a *bean* (the DTO). Parsing into raw `Map<String,Object>` accepts any structure, including deeply-nested or very large objects (no `@Size` bound). The endpoint also has no authentication requirement beyond the global chain.
- **Exploitation scenario:** A large payload causes Jackson to materialise a huge object graph in heap (CWE-400 / CWE-770 resource exhaustion). Even though the lab removed `ObjectInputStream`, a future Jackson change (e.g., enabling polymorphic typing on a shared `ObjectMapper`) would turn this into RCE again.
- **Business impact:** DoS; latent RCE risk if Jackson's `activateDefaultTyping` is ever enabled.
- **Recommended fix:** Define a strict DTO with `@Size` on the map entries; reject payloads over e.g. 16 KB; require authentication (the endpoint is currently implicitly public because `/api/login` and `/api/register` are the only explicit `permitAll` matches - `/api/deserialize` is therefore `authenticated()`). Consider deleting the endpoint entirely in production builds.
- **Remediation status:** Not Applied

### S10 - `CommentController.greet` builds HTML by string concatenation

- **Severity:** Medium
- **CWE:** CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **OWASP Top 10 (2021):** A03 Injection (XSS)
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentController.java`
- **Method / Class:** `greet(String)`
- **Evidence (lines 57-63):**
  ```java
  @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
  public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
      // REMEDIATION (A03:2021 - XSS): HTML-escape the user-controlled
      // value before concatenating it into the response.
      String safe = HtmlUtils.htmlEscape(name);
      return "<html><body><h1>Hello, " + safe + "!</h1></body></html>";
  }
  ```
- **Root cause:** The input *is* HTML-escaped via `HtmlUtils.htmlEscape`. The remaining risk is that the endpoint still hand-builds HTML strings rather than rendering a Thymeleaf / Mustache template. There is no `Content-Security-Policy` enforcement on this path (the CSP set in `SecurityConfig` applies to the *whole* chain, but the inline HTML produced here would be blocked by `script-src 'self'` if the response were ever a script context). `HtmlUtils.htmlEscape` does not escape `'`, which is a concern for any future attribute interpolation.
- **Exploitation scenario:** A future refactor that moves the value into an HTML attribute (e.g., `<div title="...">`) without re-escaping re-introduces XSS. `HtmlUtils.htmlEscape` is a *string-context* escaper, not a full HTML sanitizer.
- **Business impact:** Latent reflected XSS; the only thing keeping the endpoint safe today is the developer's discipline, not the type system.
- **Recommended fix:** Move to a templating engine (Thymeleaf) and pass the value as `${param.name}` so the engine handles context-correct escaping. Add a regression test that sends `<script>alert(1)</script>` and asserts the response body is escaped.
- **Remediation status:** Not Applied (latent - the active code is escaped, the issue is the construction style).

### S11 - `CommentViewController` builds HTML by string concatenation

- **Severity:** Medium
- **CWE:** CWE-79
- **OWASP Top 10 (2021):** A03 Injection (XSS)
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentViewController.java`
- **Method / Class:** `viewAll()` and `viewOne(Long)`
- **Evidence (lines 33-48):**
  ```java
  @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
  public String viewAll() {
      StringBuilder sb = new StringBuilder();
      sb.append("<html><body><h1>Comments</h1>");
      List<Comment> comments = commentService.findAll();
      for (Comment c : comments) {
          sb.append("<div class='comment'>")
            .append("<b>").append(HtmlUtils.htmlEscape(c.getAuthor())).append(":</b> ")
            .append(HtmlUtils.htmlEscape(c.getBody()))
            .append("</div>");
      }
      sb.append("</body></html>");
      return sb.toString();
  }
  ```
- **Root cause:** Same as S10 - escaping is done but the controller builds the document by hand. A future change that adds an attribute (e.g., `<a href="...">`, `<img src="...">`, `<div style="...">`) drops the escaping guarantee. The `class='comment'` attribute is hard-coded so it isn't a current XSS, but `Comment.body` allows up to 2000 characters and is rendered into the same template - combined with `getAuthor()` (not validated at all on write), this is a stored-XSS sink waiting for a refactor mistake.
- **Exploitation scenario:** A future maintainer adds an `@RequestParam` "format" flag that switches between `text` and `html` rendering; the `html` branch re-introduces unescaped output.
- **Business impact:** Stored XSS in the comment view.
- **Recommended fix:** Use a templating engine; never accept a "render as HTML" flag from the client. Hard-set the response `Content-Type: text/html; charset=UTF-8` and `X-Content-Type-Options: nosniff` (already set globally via `SecurityConfig`).
- **Remediation status:** Not Applied (latent)

### S12 - No CSRF protection on Basic-auth + STATELESS API

- **Severity:** Low
- **CWE:** CWE-352 Cross-Site Request Forgery
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Evidence (lines 61-70):**
  ```java
  .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
  .csrf(csrf -> csrf
          .ignoringRequestMatchers(
                  new AntPathRequestMatcher("/h2-console/**")
          )
  )
  ```
- **Root cause:** `STATELESS` + HTTP Basic means there is no session cookie, so traditional CSRF does not apply. **However**, browsers will still attach `Authorization: Basic ...` headers to cross-origin requests if the user is tricked into making them (this is the well-known "Basic auth CSRF / side-channel" pattern), and the `h2-console/**` matcher is the only explicit CSRF-ignore - but since CSRF protection is on by default for *all other* endpoints, this is fine. The remaining risk is the *latent* one: if a future change adds a session-cookie login (e.g., `formLogin()`), CSRF is enabled by default, which is correct, but no test enforces this. The finding is informational/low.
- **Exploitation scenario:** Cross-origin `fetch(..., {credentials:'include'})` with a captured Basic header; this requires the attacker to have already captured the header.
- **Business impact:** Negligible today; this finding is documentation-grade.
- **Recommended fix:** Add a `@WebMvcTest` that asserts `csrf().disable()` is **not** present; add a regression test for the `h2-console` opt-in chain.
- **Remediation status:** Not Applied (low)

### S13 - `AuthController.register` uses `Map<String,String>` with no validation

- **Severity:** Medium
- **CWE:** CWE-20 Improper Input Validation
- **OWASP Top 10 (2021):** A04 Insecure Design
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Method / Class:** `register(Map<String,String>)`
- **Evidence (lines 72-86):**
  ```java
  @PostMapping("/register")
  public ResponseEntity<User> register(@RequestBody Map<String, String> body) {
      String username = body.getOrDefault("username", "");
      String password = body.getOrDefault("password", "");
      String email    = body.getOrDefault("email", "");

      User u = new User(username, passwordEncoder.encode(password), email, "USER", 0.0);
      return ResponseEntity.ok()
              .cacheControl(CacheControl.noStore())
              .body(userService.save(u));
  }
  ```
- **Root cause:** The controller does not validate `username` (length, charset, uniqueness - uniqueness is enforced by the DB column `@Column(unique=true)` but the failure mode is a 500 with the JPA exception), `password` (no length floor; a one-character password is accepted), or `email` (no format check, no `@Email`). Compare with the `ProductCreateRequest` and `CommentCreateRequest` DTOs which both have `@NotBlank` / `@Size` / `@Positive`.
- **Exploitation scenario:** Attacker creates 10k accounts with one-character passwords to enumerate or fill the in-memory H2 store; the DB is bounded only by JVM heap.
- **Business impact:** Resource exhaustion; account-enumeration surface; non-conformance with the lab's own DTO pattern.
- **Recommended fix:** Introduce a `RegisterRequest` DTO with `@NotBlank @Size(min=3, max=64)`, `@NotBlank @Size(min=12, max=128) @ToStringPassword`, and `@Email` on the email field. Catch `DataIntegrityViolationException` and return 409.
- **Remediation status:** Not Applied

### S14 - `AuthController.transfer` uses `Map<String,Object>` with manual casts

- **Severity:** Medium
- **CWE:** CWE-20
- **OWASP Top 10 (2021):** A04 Insecure Design
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Method / Class:** `transfer(Map<String,Object>, UserDetails)`
- **Evidence (lines 88-93):**
  ```java
  @PostMapping("/transfer")
  public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body,
                                     @AuthenticationPrincipal UserDetails caller) {
      Long fromId = ((Number) body.get("fromId")).longValue();
      Long toId   = ((Number) body.get("toId")).longValue();
      Double amount = ((Number) body.get("amount")).doubleValue();
  ```
- **Root cause:** No `@Valid`, no DTO, no Jackson coercion handling. A missing key raises `NullPointerException` (auto-500 with the configured `include-stacktrace=never`, but the error message will leak "Required request body is missing of type Map" or similar). A non-numeric `amount` raises `ClassCastException`. A `String`-typed `amount` (`"amount": "1e308"`) is silently accepted by Jackson's `Number` cast.
- **Exploitation scenario:** Crashes are used to probe field names; an attacker can flood `/api/transfer` with malformed payloads to fill logs.
- **Business impact:** Information disclosure in error path; DoS via exception storms.
- **Recommended fix:** Define a `TransferRequest` DTO with `@NotNull @Positive @DecimalMax("1000000.0") Double amount`, `@NotNull Long fromId`, `@NotNull Long toId`. Add a `@ControllerAdvice` that maps validation failures to 400 with a stable schema.
- **Remediation status:** Not Applied

### S15 - `UserController.search` accepts un-validated `q`

- **Severity:** Low
- **CWE:** CWE-20
- **OWASP Top 10 (2021):** A04 Insecure Design
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\UserController.java`
- **Method / Class:** `search(String)`
- **Evidence (lines 71-77):**
  ```java
  @GetMapping("/search")
  public ResponseEntity<List<User>> search(@RequestParam("q") String q) {
      return ResponseEntity.ok()
              .cacheControl(CacheControl.noStore())
              .body(userService.findByUsernameUnsafe(q));
  }
  ```
- **Root cause:** No `@NotBlank`, no `@Size(max=...)`. The query reaches a parameterised native SQL (`UserService.java` line 40), so SQLi is not a risk, but the endpoint will execute a full-table scan for `%`-style payloads and accept arbitrarily long strings.
- **Exploitation scenario:** `?q=%25` returns every user; `?q=` (empty) returns nothing but issues a query; billion-laughs on a very long `q`.
- **Business impact:** Slow query DoS; data over-fetch.
- **Recommended fix:** Add `@NotBlank @Size(max=64) String q` via `@Validated` on the controller; trim and reject if `q.contains("%")` is not a feature.
- **Remediation status:** Not Applied

### S16 - `UserController.getProfile` returns 404 on missing user, 200 on forbidden - minor info leak

- **Severity:** Low
- **CWE:** CWE-200 Information Disclosure
- **OWASP Top 10 (2021):** A01 Broken Access Control
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\UserController.java`
- **Method / Class:** `getProfile(Long, UserDetails)`
- **Evidence (lines 57-65):**
  ```java
  User target = userService.findByIdUnsafe(id);
  if (target == null) {
      return ResponseEntity.notFound().build();
  }
  boolean isAdmin = caller.getAuthorities().stream()
          .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
  if (!isAdmin && !caller.getUsername().equals(target.getUsername())) {
      throw new AccessDeniedException("Cannot view another user's profile");
  }
  ```
- **Root cause:** The 404/403 dichotomy lets an attacker distinguish "no such user" from "this user exists but you can't see it". Minor; common in REST APIs.
- **Exploitation scenario:** Probe `id` values to enumerate which user IDs exist.
- **Business impact:** Account enumeration.
- **Recommended fix:** Always return 404 (or 403) regardless of existence. Or use the service-layer `findByIdForCaller` and return its `null`.
- **Remediation status:** Not Applied

### S17 - Login-failure log lacks username / source IP

- **Severity:** Low
- **CWE:** CWE-778 Insufficient Logging
- **OWASP Top 10 (2021):** A09 Security Logging & Monitoring Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- **Evidence (lines 53-56):**
  ```java
  org.slf4j.LoggerFactory.getLogger(AuthController.class)
          .warn("Failed login attempt for username of length {}",
                  username == null ? 0 : username.length());
  ```
- **Root cause:** Logs only the *length* of the username. A SIEM cannot correlate attempts against a specific user, and the rate-limit filter is the only place the source IP is captured (and that is in-memory only, see S6).
- **Recommended fix:** Log the username (or its SHA-256) and the source IP; emit a structured log event (`log.warn("auth.fail", kv("user", user), kv("ip", ip))`).
- **Remediation status:** Not Applied

### S18 - `DataSeeder` runs in every profile

- **Severity:** Medium
- **CWE:** CWE-1188 Insecure Default Initialization
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\DataSeeder.java`
- **Evidence (lines 26-30):**
  ```java
  @Bean
  CommandLineRunner seed(UserRepository userRepository,
                         ProductRepository productRepository,
                         CommentRepository commentRepository,
                         PasswordEncoder passwordEncoder) {
  ```
- **Root cause:** No `@Profile("sandbox")` and no `@ConditionalOnProperty`. The seeder is a top-level `@Configuration` and runs on every startup, including any future production deployment of this artifact.
- **Exploitation scenario:** Operators who "just run the jar" in a public environment will have the admin account present.
- **Business impact:** Default-credential access in prod.
- **Recommended fix:** Add `@Profile("!prod & sandbox")` or `@ConditionalOnProperty(name="app.seed.enabled", havingValue="true", matchIfMissing=false)`.
- **Remediation status:** Not Applied

### S19 - No HTTP security headers at the controller level

- **Severity:** Informational
- **CWE:** CWE-693 Protection Mechanism Failure
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **Files:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- **Evidence (lines 73-85):** Headers are configured at the filter chain level. CSP is set, HSTS is set, X-Content-Type-Options / X-Frame-Options / Referrer-Policy are set, but `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, and `Cross-Origin-Resource-Policy` are not. There is no `X-Permitted-Cross-Domain-Policies: none`.
- **Root cause:** Defence-in-depth header set is incomplete; relying solely on Spring Security defaults means any future endpoint registered outside the chain (e.g., a custom `WebMvcConfigurer` addResourceHandler) bypasses the headers.
- **Recommended fix:** Add the missing headers via a `OncePerRequestFilter` registered with `FilterRegistrationBean` at high precedence; pin CSP to `default-src 'none'` for endpoints that do not need scripts.
- **Remediation status:** Not Applied

### S20 - `VulnerabilityController` is publicly reachable

- **Severity:** Informational
- **CWE:** CWE-200 Information Disclosure
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\VulnerabilityController.java`
- **Evidence (lines 22-59):** Returns a public HTML page that lists every vulnerable endpoint in the application, including the de-remediated history.
- **Root cause:** Lab-only documentation. In a real deployment, this would be a recon goldmine.
- **Recommended fix:** Remove the controller for non-lab profiles (`@Profile("sandbox")`); never deploy the controller.
- **Remediation status:** Not Applied

### S21 - No `@ControllerAdvice` global exception handler

- **Severity:** Informational
- **CWE:** CWE-209 Generation of Error Message Containing Sensitive Information
- **OWASP Top 10 (2021):** A09 Security Logging & Monitoring Failures
- **Files:** entire `controller` package
- **Root cause:** `AccessDeniedException` thrown by `AuthController.transfer` (line 98, 109) and `UserController.listUsers` (line 44), `UserController.getProfile` (line 55, 64) reaches Spring's default error attributes. The properties set `server.error.include-stacktrace=never` and `server.error.include-message=never`, which suppresses the *body*, but the *status* (`403`) and the *path* still appear in the error log. There is no controller advice to map domain exceptions to stable JSON envelopes.
- **Recommended fix:** Add a `@RestControllerAdvice` that maps `AccessDeniedException` to 403, `MethodArgumentNotValidException` to 400, and `DataIntegrityViolationException` to 409; log at WARN with the principal name and the request path.
- **Remediation status:** Not Applied

---

## 4. Dependency & Configuration Findings

### D1 - `spring-boot-starter-parent` 3.2.5 (no live CVE scan run)

- **Severity:** Medium
- **CWE:** CWE-1104 Use of Unmaintained Third-Party Components
- **OWASP Top 10 (2021):** A06 Vulnerable & Outdated Components
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\pom.xml`
- **Evidence (lines 14-19):**
  ```xml
  <parent>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-parent</artifactId>
      <version>3.2.5</version>
      <relativePath/>
  </parent>
  ```
- **Root cause:** Spring Boot 3.2.5 was released in 2024; the 3.2.x line is now in OSS support / end-of-life per Spring's support policy. Several CVEs have been filed against 3.2.x prior patch releases. We did not run `mvn dependency-check:check` in this assessment, so we cannot enumerate them authoritatively.
- **Recommended fix:** Bump to the latest 3.2.x patch (or 3.3.x / 3.4.x if the dependency surface allows). Wire `dependency-check-maven` into `verify` so the build fails on CVEs.
- **Remediation status:** Not Applied

### D2 - H2 2.x (no live CVE scan run)

- **Severity:** Low
- **CWE:** CWE-1104
- **OWASP Top 10 (2021):** A06 Vulnerable & Outdated Components
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\pom.xml`
- **Evidence (lines 59-63):**
  ```xml
  <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <scope>runtime</scope>
  </dependency>
  ```
- **Root cause:** The H2 version is inherited from the Spring Boot BOM (managed by `spring-boot-dependencies` 3.2.5). H2 has had multiple historical CVEs (e.g., CVE-2021-23463, CVE-2022-23221, CVE-2018-10054). Live CVE feed not consulted.
- **Recommended fix:** Pin to the latest 2.x release; do not ship H2 in prod (`<scope>runtime</scope>` should be replaced with a profile that excludes it).
- **Remediation status:** Not Applied

### D3 - `dependency-check-maven` is not bound to a phase

- **Severity:** Medium
- **CWE:** CWE-1104
- **OWASP Top 10 (2021):** A06 Vulnerable & Outdated Components
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\pom.xml`
- **Evidence (lines 101-108):**
  ```xml
  <plugin>
      <groupId>org.owasp</groupId>
      <artifactId>dependency-check-maven</artifactId>
      <version>9.2.0</version>
      <configuration>
          <failBuildOnAnyVulnerability>false</failBuildOnAnyVulnerability>
      </configuration>
  </plugin>
  ```
- **Root cause:** The plugin is declared but not bound to any phase; `<failBuildOnAnyVulnerability>false</failBuildOnAnyVulnerability>` is the default and the plugin is not registered in `<executions>`. A regular `mvn verify` will never invoke it. The comment in `pom.xml` (lines 94-100) acknowledges this is an opt-in scan.
- **Recommended fix:** Add `<executions><execution><goals><goal>check</goal></goals></execution></executions>` and set `<failBuildOnAnyVulnerability>true</failBuildOnAnyVulnerability>` (or a CVSS threshold). Pin a NVD mirror.
- **Remediation status:** Not Applied

### C1 - `spring.datasource.password=` empty

- **Severity:** Informational
- **CWE:** CWE-1188
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Evidence (lines 17-20):**
  ```
  spring.datasource.url=jdbc:h2:mem:owaspdb;DB_CLOSE_DELAY=-1
  spring.datasource.driver-class-name=org.h2.Driver
  spring.datasource.username=sa
  spring.datasource.password=
  ```
- **Root cause:** Empty password is correct for in-memory H2 `sa`, but the `datasource` block is not a profile-gated block - if a non-sandbox profile overrides the URL to a real database, the empty password remains a real (and silent) footgun.
- **Recommended fix:** Move the H2 block into a `application-sandbox.properties` and activate it via `--spring.profiles.active=sandbox`; in `application.properties` leave only `${SPRING_DATASOURCE_PASSWORD}` and require it at startup.
- **Remediation status:** Not Applied

### C2 - `spring.jpa.hibernate.ddl-auto=create`

- **Severity:** Low
- **CWE:** CWE-1188
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Evidence (line 37):**
  ```
  spring.jpa.hibernate.ddl-auto=create
  ```
- **Root cause:** `create` drops and recreates the schema on every restart. If this profile is ever pointed at a real DB, the application will silently wipe data.
- **Recommended fix:** Default to `validate`; gate `create`/`create-drop` on a `sandbox` profile.
- **Remediation status:** Not Applied

### C3 - Error attribute keys not fully pinned

- **Severity:** Low
- **CWE:** CWE-209
- **OWASP Top 10 (2021):** A05 Security Misconfiguration
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Evidence (lines 54-55):**
  ```
  server.error.include-stacktrace=never
  server.error.include-message=never
  ```
- **Root cause:** `include-binding-errors` and `include-exception` are not set; the default for both is `never`, but explicit pinning is defence-in-depth. Also, the response is not gated on `/error` being authenticated (it is in the `permitAll` list, which is correct for an error page but means the error *path* is reachable without auth).
- **Recommended fix:** Add `server.error.include-binding-errors=never` and `server.error.include-exception=false` explicitly. Consider a `@ControllerAdvice` that returns a stable JSON envelope.
- **Remediation status:** Not Applied

### C4 - `app.secret.jwt.signing.key` defaults to empty string

- **Severity:** High
- **CWE:** CWE-321
- **OWASP Top 10 (2021):** A02 Cryptographic Failures
- **File:** `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties`
- **Evidence (line 34):**
  ```
  app.secret.jwt.signing.key=${APP_SECRET_JWT_SIGNING_KEY:}
  ```
- **Root cause:** Same as S2. The placeholder defaults to empty; no minimum-length check at startup.
- **Recommended fix:** Use a non-empty `defaultValue` that throws at startup (or omit the default and let `@Value` throw); add a `@PostConstruct` length check in `SecretConfig`.
- **Remediation status:** Not Applied

---

## 5. OWASP Top 10 (2021) Mapping

| OWASP 2021 | Findings |
|---|---|
| A01 Broken Access Control | S7, S16 |
| A02 Cryptographic Failures | S1, S2, C4 |
| A03 Injection (XSS) | S10, S11 |
| A04 Insecure Design | S6, S13, S14, S15 |
| A05 Security Misconfiguration | S4, S5, S8, S12, S18, S19, S20, C1, C2, C3 |
| A06 Vulnerable & Outdated Components | D1, D2, D3 |
| A07 Identification & Authentication Failures | S3 |
| A08 Software & Data Integrity Failures | S9 |
| A09 Security Logging & Monitoring Failures | S5, S17, S21 |
| A10 SSRF | (none observed) |

---

## 6. CWE Mapping

| CWE | Findings |
|---|---|
| CWE-20 Improper Input Validation | S13, S14, S15 |
| CWE-79 XSS | S10, S11 |
| CWE-200 Information Disclosure | S16, S20 |
| CWE-209 Error Message Information Disclosure | S21, C3 |
| CWE-306 Missing Authentication for Critical Function | S4, S8 |
| CWE-319 Cleartext Transmission | S1 |
| CWE-321 Hard-coded / Predictable Cryptographic Key | S2, C4 |
| CWE-348 Use of Less Trusted Source | S6 |
| CWE-352 CSRF | S12 |
| CWE-502 Deserialization of Untrusted Data | S9 |
| CWE-521 Weak Password Requirements | S3 |
| CWE-532 Sensitive Information in Log | S5 |
| CWE-639 Authorization Bypass Through User-Controlled Key | S7 |
| CWE-693 Protection Mechanism Failure | S19 |
| CWE-770 Allocation of Resources Without Limits | S6 |
| CWE-778 Insufficient Logging | S17 |
| CWE-1104 Unmaintained Third-Party Components | D1, D2, D3 |
| CWE-1188 Insecure Default Initialization | S4, S8, S18, C1, C2 |

---

## 7. Priority Remediation Roadmap

Ordered Critical -> Low. **This run did not apply any of the following.** The remediation agent (downstream) should consume this section.

1. **S2 / C4 - JWT signing key may be empty** (High). Validate at startup: `if (jwtSigningKey == null || jwtSigningKey.length() < 32) throw new IllegalStateException(...)`. Change `application.properties` to require the env var (`app.secret.jwt.signing.key=${APP_SECRET_JWT_SIGNING_KEY}` with no default).
2. **S4 / S8 - H2 console opt-in is unauthenticated** (High). Replace `permitAll` on `/h2-console/**` with `hasRole('ADMIN')` and Basic auth, or remove the chain entirely and add a profile-gated H2 Maven dependency.
3. **S1 - HTTP Basic without TLS** (High). Add `server.ssl.*` to `application.properties`; terminate TLS at a proxy in production. Replace HTTP Basic with a token-based scheme in a follow-up.
4. **S3 - Seed admin account** (High). Gate `DataSeeder` on `@Profile("sandbox")`; emit a WARN log on every seed. Move seed passwords to a generated random value.
5. **S7 - `findByIdUnsafe` retained** (High). Delete the deprecated method; route every call through `findByIdForCaller`.
6. **S6 - Rate limiter bypass via path and `X-Forwarded-For`** (Medium). Use `AntPathRequestMatcher("/api/login")`; read forwarded IP only from a trusted proxy CIDR; back the counter with Redis/Bucket4j.
7. **S18 - `DataSeeder` not profile-gated** (Medium). `@Profile("!prod")` or `@ConditionalOnProperty`.
8. **D1 / D3 - Spring Boot 3.2.5 + unscanned dependencies** (Medium). Bump to latest 3.2.x; bind `dependency-check-maven` to `verify` with a CVSS threshold.
9. **S5 / S17 / S21 - Logging** (Medium / Low). Add structured audit events; add `@RestControllerAdvice`.
10. **S9 - `Map.class` deserialization** (Medium). Replace with a strict DTO; cap request body size; require auth.
11. **S10 / S11 - Hand-built HTML** (Medium). Migrate to Thymeleaf; add `nosniff` regression test.
12. **S13 / S14 - `Map<String,Object>` controllers** (Medium). Introduce `RegisterRequest` and `TransferRequest` DTOs with `@Valid`.
13. **S15 - Un-validated `q`** (Low). `@Validated` + `@Size(max=64)` on `UserController.search`.
14. **S12 / S16 / S19 / S20 / C1 / C2 / C3** (Low / Informational). Apply the per-finding recommendations; treat as backlog.
15. **D2 - H2 CVE** (Low). Pin a known-good 2.x version; do not ship H2 to prod.
16. **C2 / C3 - `ddl-auto=create` and error attributes** (Low). Gate on `sandbox`; pin error attributes.

---

## 8. Appendix: File Inventory Scanned

### Java sources (read in full)

- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\VulnerableSpringAppApplication.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\DataSeeder.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\JpaUserDetailsService.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecurityConfig.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\PasswordConfig.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\SecretConfig.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\config\LoginRateLimitFilter.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\AuthController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\UserController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\ProductController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\CommentViewController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\InsecureDeserializationController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\controller\VulnerabilityController.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\UserService.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\ProductService.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\service\CommentService.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\repository\UserRepository.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\repository\ProductRepository.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\repository\CommentRepository.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\model\User.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\model\Product.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\model\Comment.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\dto\ProductCreateRequest.java`
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\java\com\owasp\lab\dto\CommentCreateRequest.java`

### Build / config

- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\pom.xml` (read in full)
- `C:\Users\Lenovo\Downloads\sprint_boot_applications_demo_git\src\main\resources\application.properties` (read in full)

### Confirmed absent (no scan required)

- `application.yml` / `application.yaml` - none in tree (`Glob **/*.yml` returned no matches).
- Thymeleaf templates - none (`Glob **/templates/**` returned no matches).
- Static assets - none (`Glob **/static/**` returned no matches).
- Test sources - none (`Glob **/test/**/*` returned no matches).
- Build descriptor other than `pom.xml` - no `build.gradle*` exists.

### Skipped (out of scope)

- `target/classes/application.properties` - build output.
- `.claude/**` - agent contracts, not application source.
- `.github/workflows/build-and-security.yml` - CI script; not opened in this scan (the `pom.xml` is the authoritative source for build plugins).
