package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponse {
    private UUID userId;
    private String username;
    private String email;
    private Map<String, ServiceInfo> services;
    private String profileImageUrl; // optional: from oauth_accounts for Google or other providers
    private boolean hasPassword; // true if user has set a local password
    private List<String> authProviders; // e.g., ["LOCAL", "GOOGLE"]
    private boolean mfaEnabled; // true if MFA is enabled for the user

    // Constructor without MFA for backward compatibility
    public UserInfoResponse(UUID userId, String username, String email, Map<String, ServiceInfo> services,
                           String profileImageUrl, boolean hasPassword, List<String> authProviders) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.services = services;
        this.profileImageUrl = profileImageUrl;
        this.hasPassword = hasPassword;
        this.authProviders = authProviders;
        this.mfaEnabled = false;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ServiceInfo {
        private String plan;
        private String status;
        private LocalDate expiryDate;
    }
}
