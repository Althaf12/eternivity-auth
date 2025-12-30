package com.eternivity.auth.controller;

import com.eternivity.auth.security.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller to expose JWT signing key for downstream services.
 * This allows other *.eternivity.com services to validate JWTs
 * without accessing the auth database.
 *
 * SECURITY NOTE: This endpoint should be protected at the network level
 * (e.g., only accessible from internal services via API gateway or VPC).
 * Do not expose this endpoint to the public internet in production.
 */
@RestController
@RequestMapping("/api/auth")
public class JwkController {

    private final JwtTokenProvider tokenProvider;

    public JwkController(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Returns the JWT signing key (Base64 encoded) for downstream services.
     *
     * Downstream services should:
     * 1. Cache this key with a reasonable TTL (e.g., 1 hour)
     * 2. Use it to validate JWT signatures
     * 3. Handle key rotation by refreshing the cache
     */
    @GetMapping("/jwk")
    public ResponseEntity<Map<String, Object>> getJwk() {
        Map<String, Object> response = new HashMap<>();
        response.put("kty", "oct"); // Key type: symmetric
        response.put("alg", "HS256");
        response.put("k", tokenProvider.getEncodedSecretKey());
        response.put("use", "sig"); // Signature use

        Map<String, Object> wrapper = new HashMap<>();
        wrapper.put("keys", new Object[]{response});

        return ResponseEntity.ok(wrapper);
    }
}

