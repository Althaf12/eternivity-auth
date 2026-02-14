package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for MFA-related operations.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MfaResponse {

    private boolean success;
    private String message;
    private boolean mfaEnabled;

    public static MfaResponse success(String message, boolean mfaEnabled) {
        return new MfaResponse(true, message, mfaEnabled);
    }

    public static MfaResponse error(String message) {
        return new MfaResponse(false, message, false);
    }
}

