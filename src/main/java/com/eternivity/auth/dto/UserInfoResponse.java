package com.eternivity.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ServiceInfo {
        private String plan;
        private String status;
    }
}
