package com.owasp.lab.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

/**
 * User entity.
 *
 * REMEDIATION (OWASP A02:2021 - Cryptographic Failures /
 *              OWASP A07:2021 - Identification and Authentication Failures):
 * The {@code password} column stores a hashed credential produced by the
 * configured {@link org.springframework.security.crypto.password.PasswordEncoder}
 * (BCrypt by default).  Plaintext passwords never reach the database.
 *
 * <p>REMEDIATION (OWASP A04:2021 - Insecure Design / A01:2021 - Mass Assignment):
 * the {@code password} field is annotated {@code @JsonIgnore} so that no
 * endpoint which returns the {@code User} entity leaks the credential hash
 * (see VULN-010).  The {@code setPassword} method is preserved for
 * internal service-layer callers (e.g. password reset) but is
 * {@code @JsonIgnore}-protected on the inbound side as well.</p>
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    private String email;
    private String role;        // e.g. "USER", "ADMIN"
    private Double balance;     // for /transfer demo

    public User() {}

    public User(String username, String password, String email, String role, Double balance) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.balance = balance;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    @JsonIgnore
    public String getPassword() { return password; }

    @JsonIgnore
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    // REMEDIATION (OWASP A04:2021 - Insecure Design / A01:2021 - Mass Assignment):
    // VULN-007 - the setRole / setBalance setters are annotated
    // @JsonIgnore so Jackson will NEVER populate role or balance from
    // a request body.  Future endpoints that bind to User (e.g. an
    // admin-update endpoint) cannot be tricked into accepting
    // {"role":"ADMIN","balance":1e9}.  Internal callers (e.g.
    // AuthController.transfer) still invoke setBalance() directly
    // and continue to work because @JsonIgnore only affects Jackson
    // binding, not Java access.
    public String getRole() { return role; }

    @JsonIgnore
    public void setRole(String role) { this.role = role; }

    public Double getBalance() { return balance; }

    @JsonIgnore
    public void setBalance(Double balance) { this.balance = balance; }
}
