package com.owasp.lab.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/**
 * REMEDIATION (OWASP A04:2021 - Insecure Design / CWE-20):
 * A dedicated request DTO for the /api/transfer endpoint that:
 *  - replaces the previous raw {@code Map<String,Object>} with
 *    a typed POJO so Jackson coerces the values safely and
 *    missing or non-numeric fields fail with HTTP 400 instead
 *    of leaking a {@link NullPointerException} or
 *    {@link ClassCastException} in the response;
 *  - bounds the transfer amount ({@code @Positive},
 *    {@code @DecimalMax}) so a request with a missing
 *    {@code fromId}, {@code toId}, or {@code amount} is rejected
 *    before the controller body runs;
 *  - prevents mass-assignment of any other entity field by
 *    declaring only the three allowed keys.
 */
public class TransferRequest {

    @NotNull
    private Long fromId;

    @NotNull
    private Long toId;

    @NotNull
    @Positive
    @DecimalMax("1000000.0")
    private Double amount;

    public TransferRequest() {}

    public Long getFromId() { return fromId; }
    public void setFromId(Long fromId) { this.fromId = fromId; }

    public Long getToId() { return toId; }
    public void setToId(Long toId) { this.toId = toId; }

    public Double getAmount() { return amount; }
    public void setAmount(Double amount) { this.amount = amount; }
}
