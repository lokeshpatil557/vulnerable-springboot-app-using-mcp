package com.owasp.lab.controller;

import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * User-related REST endpoints.
 *
 * REMEDIATION (OWASP A01:2021 - Broken Access Control / IDOR):
 *  - /api/users is restricted to ADMIN role.
 *  - /api/profile/{id} requires the caller to be the resource owner
 *    OR an ADMIN.
 *  - /api/search continues to use parameterised SQL (see UserService)
 *    and is restricted to authenticated users.
 *
 * REMEDIATION (OWASP A05:2021 - Security Misconfiguration):
 *  - VULN-009: every authenticated response sets
 *    Cache-Control: no-store so browsers / proxies do not retain
 *    profile, user-list, or search-result pages that may include PII.
 */
@RestController
@RequestMapping("/api")
@Validated
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> listUsers(@AuthenticationPrincipal UserDetails caller) {
        // REMEDIATION (A01:2021): only ADMIN can enumerate every user.
        if (caller == null || caller.getAuthorities().stream()
                .noneMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            throw new AccessDeniedException("ADMIN role required");
        }
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(userService.findAll());
    }

    @GetMapping("/profile/{id}")
    public ResponseEntity<User> getProfile(@PathVariable Long id,
                                           @AuthenticationPrincipal UserDetails caller) {
        if (caller == null) {
            throw new AccessDeniedException("Authentication required");
        }
        // REMEDIATION (A01:2021 / A05:2021 - CWE-639 / CWE-200):
        // Route through the authorisation-aware service lookup. The
        // service returns null for BOTH "no such user" and
        // "forbidden", so we return 404 in both cases and do not
        // distinguish them for an attacker.
        boolean isAdmin = caller.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        User target = userService.findByIdForCaller(id, caller.getUsername(), isAdmin);
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(target);
    }

    @GetMapping("/search")
    public ResponseEntity<List<User>> search(
            // REMEDIATION (A04:2021 - CWE-20): the query string is
            // capped and required. The underlying query is
            // parameterised, so SQL injection is not possible, but
            // an unbounded `q` allows slow-query DoS and data
            // over-fetch via "%"-style payloads.
            @RequestParam("q")
            @NotBlank
            @Size(min = 1, max = 64)
            String q) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(userService.findByUsernameUnsafe(q));

            }
}
