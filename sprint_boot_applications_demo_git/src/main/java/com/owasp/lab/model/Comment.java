package com.owasp.lab.model;

import jakarta.persistence.*;

/**
 * Comment entity used by the XSS demo endpoint.
 */
@Entity
@Table(name = "comments")
public class Comment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String author;

    // REMEDIATION (A03:2021 - Injection / XSS): body is stored raw, but
    // the read path (CommentViewController) HTML-escapes the value
    // before rendering. Body length is bounded at 2000 chars.
    @Column(length = 2000)
    private String body;

    public Comment() {}

    public Comment(String author, String body) {
        this.author = author;
        this.body = body;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAuthor() { return author; }
    public void setAuthor(String author) { this.author = author; }

    public String getBody() { return body; }
    public void setBody(String body) { this.body = body; }
}
