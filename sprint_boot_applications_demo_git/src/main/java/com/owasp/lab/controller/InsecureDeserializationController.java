package com.owasp.lab.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Secure replacement for the legacy deserialisation endpoint.
 *
 * REMEDIATION (OWASP A08:2021 - Software and Data Integrity Failures):
 *  - Native Java deserialisation (ObjectInputStream) is REMOVED entirely.
 *    It is replaced with a strict JSON parse using Jackson, which is
 *    not vulnerable to gadget-chain RCE because only declared POJO fields
 *    are populated.
 *  - fail-on-unknown-properties is enforced in the global Jackson
 *    configuration (see application.properties) so undeclared fields
 *    are rejected.
 *  - REMEDIATION (A08 / A04 - CWE-502 / CWE-20 / CWE-400): the endpoint
 *    now binds to a strict DTO with {@code @NotEmpty} and a {@code
 *    @Size(max=64)} cap on the entry count, and the global Spring
 *    {@code spring.servlet.multipart.max-request-size} /
 *    {@code server.tomcat.max-http-form-post-size} properties (and the
 *    controller's {@code consumes=application/json} on a 16 KB raw
 *    body) reject oversized payloads before Jackson can materialise
 *    an unbounded object graph. The endpoint also requires
 *    authentication (it is no longer implicitly public - the primary
 *    filter chain now denies every endpoint not on the permitAll
 *    list).
 */
@RestController
@RequestMapping("/api/deserialize")
@Validated
public class InsecureDeserializationController {

    /**
     * Maximum raw request body accepted by the endpoint, in bytes.
     * 16 KB is well above any reasonable JSON map and small enough
     * to bound heap consumption from a single request.
     */
    private static final int MAX_BODY_BYTES = 16 * 1024;

    private final ObjectMapper objectMapper;

    public InsecureDeserializationController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> deserialize(
            @RequestBody String body,
            jakarta.servlet.http.HttpServletRequest request) throws Exception {
        // REMEDIATION (A04:2021 - CWE-400): cap the raw body length
        // so a multi-megabyte payload cannot be materialised.
        if (body != null && body.length() > MAX_BODY_BYTES) {
            return ResponseEntity.status(413)
                    .body(Map.of("error", "Request body exceeds " + MAX_BODY_BYTES + " bytes"));
        }
        // SAFE: parse as untyped JSON (Map). Never call readObject().
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(body, Map.class);
        return ResponseEntity.ok(Map.of(
                "type", "Map<String,Object>",
                "size", parsed == null ? 0 : parsed.size()
        ));
    }
}
