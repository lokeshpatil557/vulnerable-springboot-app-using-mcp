package com.owasp.lab.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * REMEDIATION (OWASP A04:2021 - Insecure Design / A01:2021 - Broken Access Control /
 *              OWASP A20: Improper Input Validation):
 * A dedicated request DTO for product creation that:
 *  - bounds the input fields (name, description, price)
 *  - is the ONLY type the controller binds to, so the {@code id} field
 *    of the {@link com.owasp.lab.model.Product} entity can never be
 *    supplied by a client (mass-assignment mitigation).
 *  - the {@code id} field on the entity is server-generated (IDENTITY)
 *    and intentionally absent from this DTO.
 */
public class ProductCreateRequest {

    @NotBlank
    @Size(min = 1, max = 200)
    private String name;

    @Size(max = 2000)
    private String description;

    @NotNull
    @Positive
    @DecimalMax("1000000.0")
    private Double price;

    public ProductCreateRequest() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Double getPrice() { return price; }
    public void setPrice(Double price) { this.price = price; }
}
