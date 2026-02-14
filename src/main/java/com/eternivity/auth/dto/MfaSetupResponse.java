package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response when MFA setup is initiated.
 * Contains the secret and QR code for Google Authenticator.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MfaSetupResponse {

    private String secret;
    private String qrCodeUri;
    private String qrCodeImage; // Base64 encoded QR code image
    private String message;

    public MfaSetupResponse(String secret, String qrCodeUri, String qrCodeImage) {
        this.secret = secret;
        this.qrCodeUri = qrCodeUri;
        this.qrCodeImage = qrCodeImage;
        this.message = "Scan the QR code with Google Authenticator";
    }
}

