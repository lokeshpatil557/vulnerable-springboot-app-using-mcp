package com.owasp.lab.controller;

import com.owasp.lab.dto.ProductCreateRequest;
import com.owasp.lab.model.Product;
import com.owasp.lab.service.ProductService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Simple product endpoints used as additional demo targets.
 *
 * REMEDIATION (OWASP A01:2021 - Broken Access Control):
 *  - VULN-001: product creation now requires ROLE_ADMIN via
 *    {@code @PreAuthorize}. Method-level security is enabled in
 *    SecurityConfig via {@code @EnableMethodSecurity}.
 *  - VULN-002: creation binds to {@link ProductCreateRequest} (a DTO),
 *    not the entity, so the {@code id} field on {@link Product} cannot
 *    be supplied by the client and a future field added to {@code Product}
 *    will not be mass-assignable. Input is validated with
 *    {@code @Valid} (Bean Validation).
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public List<Product> list() {
        return productService.findAll();
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Product> create(@Valid @RequestBody ProductCreateRequest req) {
        Product p = new Product(req.getName(), req.getDescription(), req.getPrice());
        return ResponseEntity.ok(productService.save(p));
    }
}
