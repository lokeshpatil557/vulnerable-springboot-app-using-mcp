package com.owasp.lab.controller;

import com.owasp.lab.dto.CommentCreateRequest;
import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * Comment endpoints.
 *
 * REMEDIATION (OWASP A01:2021 - Broken Access Control / A03:2021 - XSS):
 *  - VULN-001: comment creation now requires ROLE_ADMIN via
 *    {@code @PreAuthorize}. Method-level security is enabled in
 *    SecurityConfig via {@code @EnableMethodSecurity}.
 *  - VULN-002: creation binds to {@link CommentCreateRequest} (a DTO),
 *    not the entity, so the {@code id} field on {@link Comment} cannot
 *    be set by clients and a future field added to {@code Comment} will
 *    not be mass-assignable. Input is validated with {@code @Valid}.
 *  - VULN-007: the /greet reflected-XSS sink HTML-escapes the "name"
 *    query parameter via Spring's HtmlUtils.htmlEscape.
 *  - VULN-008: stored comment bodies are escaped on the read path
 *    (see CommentViewController).
 */
@RestController
@RequestMapping("/api/comment")
public class CommentController {

    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Comment> create(@Valid @RequestBody CommentCreateRequest req,
                                          @AuthenticationPrincipal UserDetails caller) {
        String author = caller != null ? caller.getUsername() : "anonymous";
        Comment c = new Comment(author, req.getBody());
        return ResponseEntity.ok(commentService.save(c));
    }

    @GetMapping
    public List<Comment> all() {
        return commentService.findAll();
    }

    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
        // REMEDIATION (A03:2021 - XSS): HTML-escape the user-controlled
        // value before concatenating it into the response.
        String safe = HtmlUtils.htmlEscape(name);
        return "<html><body><h1>Hello, " + safe + "!</h1></body></html>";
    }
}
