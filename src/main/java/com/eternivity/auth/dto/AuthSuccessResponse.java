package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for successful authentication operations.
 * Note: Tokens are not included in the response body - they are set as HttpOnly cookies.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthSuccessResponse {
    private String message;
    private String username;
    private String email;
}

