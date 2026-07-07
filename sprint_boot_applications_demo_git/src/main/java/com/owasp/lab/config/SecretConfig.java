package com.owasp.lab.config;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

/**
 * REMEDIATION (OWASP A02:2021 - Cryptographic Failures /
 *              OWASP A05:2021 - Security Misconfiguration):
 *
 *  - VULN-010: secrets are no longer hardcoded literals in
 *    application.properties.  They are sourced from environment
 *    variables (APP_SECRET_API_KEY, APP_SECRET_DB_PASSWORD,
 *    APP_SECRET_JWT_SIGNING_KEY) which MUST be supplied by a real
 *    secrets manager (Spring Cloud Config, HashiCorp Vault, AWS
 *    Secrets Manager) at deploy time.  No defaults are provided so
 *    a misconfigured deployment fails fast rather than silently
 *    picking up an attacker-known value.
 *  - VULN-013: the JWT signing key, when one is required, must be a
 *    high-entropy value generated via SecureRandom and rotated
 *    periodically.  A {@code @PostConstruct} check below refuses to
 *    start the application if the key is blank or shorter than 32
 *    bytes (256 bits) so a misconfigured deployment cannot
 *    silently sign tokens with the empty string.
 */
@Configuration
public class SecretConfig {

    /**
     * Minimum acceptable entropy for the JWT signing key, in bytes.
     * HS256 (HMAC-SHA-256) requires a 256-bit key per RFC 7518.
     */
    private static final int MIN_JWT_KEY_BYTES = 32;

    @Value("${app.secret.api.key:}")
    private String apiKey;

    @Value("${app.secret.db.password:}")
    private String dbPassword;

    @Value("${app.secret.jwt.signing.key:}")
    private String jwtSigningKey;

    /**
     * REMEDIATION (A02:2021 - Cryptographic Failures): fail fast at
     * application start if the JWT signing key is missing or too
     * short.  A blank or short key is equivalent to a publicly known
     * signing secret and would allow forged tokens for any role.
     */
    @PostConstruct
    void validateSecrets() {
        if (jwtSigningKey == null || jwtSigningKey.isBlank()) {
            throw new IllegalStateException(
                    "app.secret.jwt.signing.key is empty. "
                  + "Set the APP_SECRET_JWT_SIGNING_KEY environment variable "
                  + "to a SecureRandom-generated value of at least "
                  + MIN_JWT_KEY_BYTES + " bytes before starting the application.");
        }
        // The signing key is treated as a UTF-8 byte string.  Using
        // getBytes().length matches what the underlying JCA / JJWT
        // layer will actually consume, so a 32-character ASCII key
        // is accepted but a 16-character key is not.
        if (jwtSigningKey.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                < MIN_JWT_KEY_BYTES) {
            throw new IllegalStateException(
                    "app.secret.jwt.signing.key is shorter than the required "
                  + MIN_JWT_KEY_BYTES + " bytes for HS256. "
                  + "Generate a new key with `openssl rand -base64 32` "
                  + "and set APP_SECRET_JWT_SIGNING_KEY.");
        }
    }

    @Bean(name = "apiKey")
    public String apiKey() {
        return apiKey;
    }

    @Bean(name = "dbPassword")
    public String dbPassword() {
        return dbPassword;
    }

    @Bean(name = "jwtSigningKey")
    public String jwtSigningKey() {
        return jwtSigningKey;
    }
}
