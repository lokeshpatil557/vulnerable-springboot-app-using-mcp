package com.owasp.lab.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * REMEDIATION (OWASP A04:2021 - Insecure Design / CWE-20):
 * A dedicated request DTO for the public /api/register endpoint that:
 *  - bounds the input fields (username, password, email);
 *  - enforces a minimum password length so a one-character
 *    password cannot create an account;
 *  - validates the email format;
 *  - is the ONLY type the controller binds to, so the {@code role}
 *    field on the {@link com.owasp.lab.model.User} entity cannot
 *    be set by the client (mass-assignment mitigation). The
 *    role is always forced to "USER" server-side.
 */
public class RegisterRequest {

    @NotBlank
    @Size(min = 3, max = 64)
    private String username;

    @NotBlank
    @Size(min = 12, max = 128)
    private String password;

    @NotBlank
    @Email
    @Size(max = 254)
    private String email;

    public RegisterRequest() {}

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}
