package com.eternivity.auth.security;

import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiration}")
    private long accessTokenExpiration; // 15 minutes in milliseconds

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExpiration; // 7 days in milliseconds

    @Value("${jwt.issuer}")
    private String issuer;

    private SecretKey signingKey;
    private final SecureRandom secureRandom = new SecureRandom();

    @PostConstruct
    public void init() {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    private SecretKey getSigningKey() {
        return signingKey;
    }

    /**
     * Generate a short-lived access token
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.getUserId().toString());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("type", "access");

        // Add services information to JWT claims
        if (user.getSubscriptions() != null && !user.getSubscriptions().isEmpty()) {
            Map<String, Map<String, String>> services = user.getSubscriptions().stream()
                .collect(Collectors.toMap(
                    UserSubscription::getServiceCode,
                    sub -> {
                        Map<String, String> serviceInfo = new HashMap<>();
                        serviceInfo.put("plan", sub.getPlan());
                        serviceInfo.put("status", sub.getStatus());
                        return serviceInfo;
                    },
                    (existing, replacement) -> existing
                ));
            claims.put("services", services);
        }

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generate a long-lived opaque refresh token (not a JWT)
     * Returns the raw token - caller should store the hash in DB
     */
    public String generateRefreshToken() {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Hash a refresh token for secure storage
     */
    public String hashRefreshToken(String refreshToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(refreshToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * @deprecated Use generateAccessToken instead
     */
    @Deprecated
    public String generateToken(User user) {
        return generateAccessToken(user);
    }

    public UUID getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return UUID.fromString(claims.getSubject());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.get("username", String.class);
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Check if token is an access token
            String tokenType = claims.get("type", String.class);
            return "access".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validate token without checking type (for backward compatibility during migration)
     */
    public boolean validateTokenSignature(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get access token expiration in seconds (for cookie max-age)
     */
    public int getAccessTokenExpirationSeconds() {
        return (int) (accessTokenExpiration / 1000);
    }

    /**
     * Get refresh token expiration in seconds (for cookie max-age)
     */
    public int getRefreshTokenExpirationSeconds() {
        return (int) (refreshTokenExpiration / 1000);
    }

    /**
     * Get refresh token expiration in milliseconds
     */
    public long getRefreshTokenExpirationMillis() {
        return refreshTokenExpiration;
    }

    /**
     * Get the JWT secret key (Base64 encoded) for downstream services
     * This allows other services to validate JWTs without accessing the auth DB
     */
    public String getEncodedSecretKey() {
        return Base64.getEncoder().encodeToString(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
}
