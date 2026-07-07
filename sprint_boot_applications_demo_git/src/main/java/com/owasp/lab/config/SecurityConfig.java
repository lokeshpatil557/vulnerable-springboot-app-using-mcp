package com.owasp.lab.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Spring Security configuration.
 *
 * REMEDIATION summary:
 *  - VULN-001: method-level security is enabled
 *    ({@code @EnableMethodSecurity}) so {@code @PreAuthorize} on
 *    product/comment creation can require ROLE_ADMIN.
 *  - VULN-005: authentication is REQUIRED for every endpoint except
 *    the explicit public list (/api/login, /api/register, /error).
 *  - VULN-011: CSRF protection is re-enabled for state-changing
 *    endpoints.
 *  - VULN-016: baseline HTTP security response headers are configured
 *    (Content-Security-Policy, X-Content-Type-Options, Referrer-Policy,
 *    X-Frame-Options, Strict-Transport-Security).
 *  - VULN-004: the /h2-console endpoint is no longer in the static
 *    {@code permitAll} list of the primary chain. A separate
 *    {@link SecurityFilterChain} bean is registered via
 *    {@code @ConditionalOnProperty} so it only activates when the
 *    {@code app.h2.console.enabled} flag is true (default false).
 *    By default the H2 console is denied.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain insecureFilterChain(HttpSecurity http) throws Exception {
        http
            // REMEDIATION (A01:2021 / A05:2021): require authentication
            // for every endpoint not explicitly listed as public.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        new AntPathRequestMatcher("/api/login"),
                        new AntPathRequestMatcher("/api/register"),
                        new AntPathRequestMatcher("/error")
                ).permitAll()
                .anyRequest().authenticated()
            )

            // REMEDIATION (A05:2021): enable HTTP Basic so the
            // AuthenticationManager (backed by the JPA user details
            // service) is exercised on every request, and the
            // @AuthenticationPrincipal injection on /api/transfer works.
            .httpBasic(basic -> {})

            // REMEDIATION (A05:2021): keep STATELESS so each request
            // must carry credentials, removing CSRF's session-cookie
            // attack surface for the JSON API.
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // REMEDIATION (A05:2021): enable CSRF for session-based
            // flows. For STATELESS Basic auth, CSRF is also enforced
            // and a 403 will be returned if a token is missing.
            .csrf(csrf -> csrf
                    .ignoringRequestMatchers(
                            new AntPathRequestMatcher("/h2-console/**")
                    )
            )

            // REMEDIATION (A05:2021): defence-in-depth response headers.
            .headers(h -> h
                    .contentSecurityPolicy(csp -> csp.policyDirectives(
                            "default-src 'self'; " +
                            "frame-ancestors 'self'; " +
                            "script-src 'self'; " +
                            "object-src 'none'"))
                    .frameOptions(f -> f.sameOrigin())
                    .referrerPolicy(r -> r.policy(
                            org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                    .ReferrerPolicy.NO_REFERRER))
                    .httpStrictTransportSecurity(hsts -> hsts
                            .includeSubDomains(true).maxAgeInSeconds(31536000))
            );

        return http.build();
    }

    /**
     * REMEDIATION (OWASP A05:2021 - Security Misconfiguration):
     * Secondary filter chain that only activates when the
     * {@code app.h2.console.enabled} property is true. The H2 web
     * console now requires ROLE_ADMIN on a Basic-auth challenge so
     * an operator who flips APP_H2_CONSOLE_ENABLED=true still has
     * to authenticate as an admin before reaching the database
     * UI. The /h2-console/** tree can therefore never be exposed
     * as a side-effect of the primary chain's {@code permitAll}
     * list, even when the env var is on.
     */
    @Bean
    @Order(0)
    @ConditionalOnProperty(name = "app.h2.console.enabled", havingValue = "true")
    public SecurityFilterChain h2ConsoleFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
            .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
            .httpBasic(basic -> {})
            .csrf(csrf -> csrf.ignoringRequestMatchers(
                    new AntPathRequestMatcher("/h2-console/**")))
            .headers(h -> h.frameOptions(f -> f.sameOrigin()));
        return http.build();
    }
}
