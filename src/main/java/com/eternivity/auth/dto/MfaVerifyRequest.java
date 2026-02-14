package com.eternivity.auth.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to verify OTP code during MFA setup or login.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MfaVerifyRequest {

    @NotBlank(message = "OTP code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "OTP must be a 6-digit number")
    @JsonAlias({"otp", "otpCode"})
    private String code;

    // Used during login flow - contains the temporary MFA token
    @JsonAlias({"mfaToken", "token"})
    private String tempToken;

    // Used during setup flow - contains the secret being verified
    private String secret;
}

