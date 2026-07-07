package com.owasp.lab.controller;

import com.owasp.lab.dto.RegisterRequest;
import com.owasp.lab.dto.TransferRequest;
import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Authentication endpoints.
 *
 * REMEDIATION summary:
 *  - VULN-002: loginUnsafe now uses parameterised SQL and a
 *    PasswordEncoder.matches() hash compare.
 *  - VULN-004: passwords are hashed on register before persistence.
 *  - VULN-006: /transfer requires authentication and verifies the
 *    caller's principal matches the source user.
 *  - VULN-009: the /api/login response no longer contains the password.
 *  - VULN-012: /register binds to a server-side DTO and the role is
 *    always forced to "USER".  ADMIN elevation requires a separate,
 *    authenticated flow.
 *  - VULN-015: failed login attempts are logged via SLF4J.
 *  - VULN-009 (cache-control): sensitive responses now set
 *    Cache-Control: no-store so browsers / proxies do not retain
 *    them.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body,
                                   HttpServletRequest request) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        User u = userService.loginUnsafe(username, password, passwordEncoder);
        if (u == null) {
            // REMEDIATION (A09:2021): emit a structured warning that
            // includes the username (or a hash of it) and the source
            // IP so brute-force attempts are correlatable in log
            // aggregation. Logging only the username length leaves a
            // SIEM unable to attribute attempts to a specific
            // account.
            log.warn("auth.fail user=\"{}\" ip={} usernameLength={}",
                    username == null ? "" : username,
                    request.getRemoteAddr(),
                    username == null ? 0 : username.length());
            return ResponseEntity.status(401)
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "Invalid credentials"));
        }
        // REMEDIATION (A04:2021 / A02:2021): never echo the password
        // (or the password hash) back to the caller.
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of(
                        "id", u.getId(),
                        "username", u.getUsername(),
                        "role", u.getRole()
                ));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        // REMEDIATION (A01:2021 / A04:2021): the role is ALWAYS forced
        // to USER server-side.  Even if the caller supplies a role
        // field, it is ignored - ADMIN elevation must go through an
        // authenticated, audited admin-only endpoint.
        User u = new User(req.getUsername(),
                          passwordEncoder.encode(req.getPassword()),
                          req.getEmail(),
                          "USER",
                          0.0);
        try {
            User saved = userService.save(u);
            return ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .body(saved);
        } catch (DataIntegrityViolationException ex) {
            // REMEDIATION (A04:2021 - CWE-20): a duplicate username
            // is reported as HTTP 409 Conflict with a stable error
            // envelope, not a 500 with the JPA exception message.
            return ResponseEntity.status(409)
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "Username already taken"));
        }
    }

    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req,
                                       @AuthenticationPrincipal UserDetails caller) {
        // REMEDIATION (A01:2021 - IDOR): the caller must own the
        // source account unless they are an ADMIN. The service-layer
        // authorisation check (findByIdForCaller) is the primary
        // gate; we keep the explicit check here as defence in depth.
        if (caller == null) {
            throw new AccessDeniedException("Authentication required");
        }
        boolean isAdmin = caller.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        User from = userService.findByIdForCaller(req.getFromId(), caller.getUsername(), isAdmin);
        if (from == null) {
            return ResponseEntity.badRequest()
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "User not found"));
        }

        // For the recipient we do not have an authorisation rule
        // (any authenticated user may transfer to any other user),
        // so the lookup is delegated to the repository. Re-use the
        // safe service method so the deprecated findByIdUnsafe is
        // never reachable.
        User to = userService.findByIdForCaller(req.getToId(), null, true);
        if (to == null) {
            return ResponseEntity.badRequest()
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "Recipient not found"));
        }
        double amount = req.getAmount();
        if (from.getBalance() < amount) {
            return ResponseEntity.badRequest()
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", "Insufficient funds"));
        }
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);
        userService.save(from);
        userService.save(to);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of(
                        "status", "ok",
                        "fromBalance", from.getBalance(),
                        "toBalance", to.getBalance()
                ));
    }
}
