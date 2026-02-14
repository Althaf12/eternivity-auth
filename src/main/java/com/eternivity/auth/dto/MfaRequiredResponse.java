package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response when login requires MFA verification.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MfaRequiredResponse {

    private String status = "MFA_REQUIRED";
    private String tempToken;
    private String message;

    public MfaRequiredResponse(String tempToken) {
        this.tempToken = tempToken;
        this.message = "MFA verification required. Please enter your 6-digit code.";
    }
}

