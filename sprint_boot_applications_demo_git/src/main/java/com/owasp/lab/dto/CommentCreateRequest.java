package com.owasp.lab.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * REMEDIATION (OWASP A04:2021 - Insecure Design / A01:2021 - Broken Access Control):
 * Dedicated DTO for comment creation so the {@code id} field on the
 * {@link com.owasp.lab.model.Comment} entity cannot be set by clients
 * (mass-assignment mitigation). The {@code author} is derived from the
 * authenticated principal on the server, not from the request body.
 */
public class CommentCreateRequest {

    @NotBlank
    @Size(min = 1, max = 2000)
    private String body;

    public CommentCreateRequest() {}

    public String getBody() { return body; }
    public void setBody(String body) { this.body = body; }
}
