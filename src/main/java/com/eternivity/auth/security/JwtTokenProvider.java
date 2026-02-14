package com.eternivity.auth.security;

import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    // Token types
    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_MFA_TEMP = "mfa_temp";

    // MFA temp token expiration: 2 minutes
    private static final long MFA_TEMP_TOKEN_EXPIRATION = 2 * 60 * 1000;

    @Autowired
    private Environment environment;

    @Value("${jwt.secret:}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiration:900000}")
    private long accessTokenExpiration; // 15 minutes in milliseconds

    @Value("${jwt.refresh-token.expiration:604800000}")
    private long refreshTokenExpiration; // 7 days in milliseconds

    @Value("${jwt.issuer:eternivity-auth}")
    private String issuer;

    private SecretKey signingKey;
    private final SecureRandom secureRandom = new SecureRandom();

    @PostConstruct
    public void init() {
        try {
            // Determine active profiles
            String[] activeProfiles = environment.getActiveProfiles();
            boolean isLocal = environment.acceptsProfiles(Profiles.of("local", "dev"));
            boolean isProd = environment.acceptsProfiles(Profiles.of("prod", "production"));

            byte[] keyBytes;

            // If jwtSecret not set via @Value, try common property/env fallbacks
            if (!StringUtils.hasText(jwtSecret)) {
                String fallback = environment.getProperty("jwt.secret");
                if (!StringUtils.hasText(fallback)) {
                    fallback = environment.getProperty("jwt_secret");
                }
                if (!StringUtils.hasText(fallback)) {
                    fallback = environment.getProperty("JWT_SECRET");
                }
                if (StringUtils.hasText(fallback)) {
                    jwtSecret = fallback;
                    log.warn("Using jwt.secret from environment/property fallback");
                }
            }

            if (!StringUtils.hasText(jwtSecret)) {
                if (isLocal) {
                    // Local development: generate a volatile key
                    byte[] randomKey = new byte[32];
                    secureRandom.nextBytes(randomKey);
                    jwtSecret = Base64.getEncoder().encodeToString(randomKey);
                    keyBytes = randomKey;
                    log.warn("No jwt.secret provided — generated a volatile development key. Do NOT use this in production.");
                } else {
                    // In production (or any non-local profile) we must have a configured secret
                    String msg = String.format("Missing required configuration property 'jwt.secret' for activeProfiles=%s. Ensure Vault/env provides 'jwt_secret' or set 'jwt.secret' in application-prod.yml or set env JWT_SECRET.", Arrays.toString(activeProfiles));
                    log.error(msg);
                    throw new IllegalStateException(msg);
                }
            } else {
                // Try Base64 decode first
                byte[] decoded = null;
                try {
                    decoded = Base64.getDecoder().decode(jwtSecret);
                } catch (IllegalArgumentException ex) {
                    decoded = null;
                }

                if (decoded != null && decoded.length >= 32) {
                    keyBytes = decoded;
                } else {
                    // Use raw UTF-8 bytes; if shorter than 32, derive a 32-byte key via SHA-256
                    keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
                    if (keyBytes.length < 32) {
                        try {
                            MessageDigest digest = MessageDigest.getInstance("SHA-256");
                            keyBytes = digest.digest(keyBytes);
                        } catch (NoSuchAlgorithmException e) {
                            byte[] padded = new byte[32];
                            System.arraycopy(keyBytes, 0, padded, 0, Math.min(keyBytes.length, 32));
                            keyBytes = padded;
                        }
                        if (isProd) {
                            String msg = String.format("Configured 'jwt.secret' is too short after decoding; provide a 32-byte (256-bit) key (base64 or raw). activeProfiles=%s", Arrays.toString(activeProfiles));
                            log.error(msg);
                            throw new IllegalStateException(msg);
                        } else {
                            log.warn("Provided jwt.secret was short; derived a 256-bit key via SHA-256 for local/testing usage.");
                        }
                    }
                }
            }

            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
            log.info("Initialized JWT signing key; activeProfiles={} ; jwtSecretConfigured={} ", (Object) Arrays.toString(activeProfiles), StringUtils.hasText(jwtSecret));
        } catch (Exception e) {
            log.error("Failed to initialize JWT signing key", e);
            throw new IllegalStateException("Failed to initialize JWT signing key: " + e.getMessage(), e);
        }
    }

    private SecretKey getSigningKey() {
        return signingKey;
    }

    /**
     * Generate a short-lived access token
     */
    public String generateAccessToken(User user) {
        return generateAccessToken(user, false);
    }

    /**
     * Generate a short-lived access token with MFA verification status
     * @param user The user
     * @param mfaVerified Whether MFA was verified during this login
     */
    public String generateAccessToken(User user, boolean mfaVerified) {
        Map<String, Object> claims = new HashMap<>();
        // Use standard subject claim for user id
        claims.put("sub", user.getUserId().toString());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("type", TOKEN_TYPE_ACCESS);

        // Add MFA claim - true if user has MFA enabled AND verified this session
        boolean mfaEnabled = Boolean.TRUE.equals(user.getMfaEnabled());
        claims.put("mfa", mfaEnabled && mfaVerified);
        claims.put("mfa_enabled", mfaEnabled);

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
     * Generate a short-lived temporary token for MFA verification.
     * This token is valid for 2 minutes and can only be used to verify MFA.
     */
    public String generateMfaTempToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.getUserId().toString());
        claims.put("username", user.getUsername());
        claims.put("type", TOKEN_TYPE_MFA_TEMP);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + MFA_TEMP_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validate MFA temporary token and return user ID if valid.
     */
    public UUID validateMfaTempToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String tokenType = claims.get("type", String.class);
            if (!TOKEN_TYPE_MFA_TEMP.equals(tokenType)) {
                return null;
            }

            return UUID.fromString(claims.getSubject());
        } catch (Exception e) {
            log.debug("Invalid MFA temp token", e);
            return null;
        }
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
            boolean isValid = "access".equals(tokenType);
            if (!isValid) {
                log.debug("Token validation failed: type='{}', expected='access'", tokenType);
            }
            return isValid;
        } catch (Exception e) {
            log.debug("Token validation failed with exception: {}", e.getMessage());
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
