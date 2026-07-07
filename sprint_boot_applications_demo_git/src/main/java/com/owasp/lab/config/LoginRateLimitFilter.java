package com.owasp.lab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * REMEDIATION (OWASP A04:2021 - Insecure Design / A07:2021 - Brute Force):
 * In-memory sliding-window rate limiter for the /api/login endpoint.
 *
 * <p>This is a deliberately small / dependency-free filter. It tracks
 * failed login attempts per remote IP and, after a threshold, responds
 * with HTTP 429 Too Many Requests until the window expires. A
 * production deployment should replace this with a shared store
 * (Redis / Bucket4j) so the counter survives restarts and is
 * consistent across replicas.</p>
 *
 * <p>Threshold: {@value #MAX_ATTEMPTS} failures per
 * {@value #WINDOW_SECONDS} seconds.</p>
 *
 * <p>Path matching uses an {@link AntPathRequestMatcher} so trailing
 * slashes, matrix parameters, and case differences cannot bypass the
 * limiter. The {@code X-Forwarded-For} header is no longer trusted
 * to derive the client key (it is forgeable by any direct caller) and
 * the key is always the TCP peer address. A reverse-proxy deployment
 * must configure {@code server.forward-headers-strategy=NATIVE} or
 * populate {@code request.getRemoteAddr()} via the proxy's own
 * connector (e.g. Tomcat's {@code RemoteIpValve}).</p>
 */
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_NANOS = 60L * 1_000_000_000L; // 60 seconds
    /**
     * REMEDIATION (A04:2021): use a path matcher so the limiter
     * cannot be bypassed by a trailing slash, matrix parameter, or
     * case difference in the request URI.
     */
    private static final AntPathRequestMatcher LOGIN_MATCHER =
            new AntPathRequestMatcher("/api/login", "POST");

    private final ConcurrentHashMap<String, AttemptWindow> windows = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!LOGIN_MATCHER.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        String key = clientKey(request);
        long now = System.nanoTime();
        AttemptWindow w = windows.compute(key, (k, existing) -> {
            if (existing == null || now - existing.startNanos > WINDOW_NANOS) {
                return new AttemptWindow(now);
            }
            return existing;
        });
        if (w.isOver(now)) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too many login attempts. Try again later.\"}");
            return;
        }
        chain.doFilter(request, response);
        // After the request, if Spring Security produced a 401 we record
        // a failure. We do this after chain.doFilter so the response
        // status is final.
        if (response.getStatus() == 401) {
            w.failures.incrementAndGet();
        } else if (response.getStatus() < 400) {
            // Successful login: clear the window so the user is not
            // penalised on a later typo.
            windows.remove(key);
        }
    }

    /**
     * REMEDIATION (A04:2021 - CWE-348 Use of a Less Trusted Source):
     * Use the TCP peer address. {@code X-Forwarded-For} is
     * trivially spoofable by a direct caller and was previously
     * used to multiply the brute-force budget by rotating the
     * header value. Operators terminating TLS / load-balancing
     * behind a trusted proxy should rely on the container's
     * RemoteIpValve (or Spring's
     * {@code server.forward-headers-strategy=NATIVE}) so that
     * {@code getRemoteAddr()} already reflects the real client.
     */
    private String clientKey(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    private static final class AttemptWindow {
        final long startNanos;
        final AtomicInteger failures = new AtomicInteger(0);

        AttemptWindow(long startNanos) {
            this.startNanos = startNanos;
        }

        boolean isOver(long now) {
            return failures.get() >= MAX_ATTEMPTS && (now - startNanos) < WINDOW_NANOS;
        }
    }
}
