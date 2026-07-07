package com.owasp.lab.service;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * User service - intentionally insecure for the OWASP learning lab.
 */
@Service
public class UserService {

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // -----------------------------------------------------------------
    // REMEDIATION (OWASP A03:2021 - Injection: SQL Injection)
    //
    // Replaced raw concatenation with a parameterised native query
    // bound via :username.  User input is treated as a literal value
    // by Hibernate and can never alter the SQL structure.
    // -----------------------------------------------------------------
    @Transactional(readOnly = true)
    public List<User> findByUsernameUnsafe(String username) {
        try {
            return entityManager
                    .createNativeQuery(
                            "SELECT * FROM users WHERE username = :username",
                            User.class)
                    .setParameter("username", username)
                    .getResultList();
        } catch (Exception ex) {
            // REMEDIATION (A09:2021): log failed lookups rather than
            // silently swallowing exceptions.
            org.slf4j.LoggerFactory.getLogger(UserService.class)
                    .warn("findByUsernameUnsafe failed for input of length {}",
                            username == null ? 0 : username.length(), ex);
            return new ArrayList<>();
        }
    }

    // -----------------------------------------------------------------
    // REMEDIATION (OWASP A07:2021 - Broken Authentication):
    // Look the user up via parameterised SQL (no concatenation), then
    // compare the supplied password against the stored hash with a
    // constant-time BCrypt match.  Plaintext credentials are no longer
    // compared by the database.
    // -----------------------------------------------------------------
    public User loginUnsafe(String username, String password,
                            org.springframework.security.crypto.password.PasswordEncoder passwordEncoder) {
        try {
            List<User> rows = entityManager
                    .createNativeQuery(
                            "SELECT * FROM users WHERE username = :username",
                            User.class)
                    .setParameter("username", username)
                    .getResultList();
            if (rows.isEmpty()) {
                return null;
            }
            User candidate = rows.get(0);
            // Constant-time hash comparison; matches() also handles the
            // {bcrypt} prefix used by DelegatingPasswordEncoder.
            if (passwordEncoder.matches(password, candidate.getPassword())) {
                return candidate;
            }
            return null;
        } catch (Exception ex) {
            org.slf4j.LoggerFactory.getLogger(UserService.class)
                    .warn("loginUnsafe failed for username of length {}",
                            username == null ? 0 : username.length(), ex);
            return null;
        }
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    // REMEDIATION (OWASP A01:2021 - Broken Access Control / IDOR):
    // The authorisation check now lives at the service boundary.
    // Callers MUST supply the authenticated principal's username and
    // either match the requested user id's owner OR hold ROLE_ADMIN.
    // Returns null both when the record is missing AND when the
    // caller is not authorised to see it, so a 404 at the controller
    // layer does not leak the existence of records.
    public User findByIdForCaller(Long id, String callerUsername, boolean callerIsAdmin) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) {
            return null;
        }
        if (callerIsAdmin) {
            return target;
        }
        if (callerUsername != null && callerUsername.equals(target.getUsername())) {
            return target;
        }
        // Return null to signal "not authorised" without leaking
        // existence of the record.
        return null;
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}
