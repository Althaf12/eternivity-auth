package com.eternivity.auth.service;

import com.eternivity.auth.entity.OAuthAccount;
import com.eternivity.auth.entity.RefreshToken;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import com.eternivity.auth.exception.OAuthAuthenticationException;
import com.eternivity.auth.repository.OAuthAccountRepository;
import com.eternivity.auth.repository.RefreshTokenRepository;
import com.eternivity.auth.repository.UserRepository;
import com.eternivity.auth.security.JwtTokenProvider;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for handling Google OAuth 2.0 authentication.
 * Handles token verification, user registration/login, and OAuth account linking.
 */
@Service
public class GoogleOAuthService {

    private static final Logger logger = LoggerFactory.getLogger(GoogleOAuthService.class);
    private static final String PROVIDER_GOOGLE = "google";

    @Value("${google.client-id:}")
    private String googleClientId;

    private final UserRepository userRepository;
    private final OAuthAccountRepository oAuthAccountRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserSubscriptionService userSubscriptionService;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;

    private GoogleIdTokenVerifier verifier;

    public GoogleOAuthService(UserRepository userRepository,
                              OAuthAccountRepository oAuthAccountRepository,
                              RefreshTokenRepository refreshTokenRepository,
                              UserSubscriptionService userSubscriptionService,
                              JwtTokenProvider tokenProvider,
                              PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.oAuthAccountRepository = oAuthAccountRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userSubscriptionService = userSubscriptionService;
        this.tokenProvider = tokenProvider;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Result for Google OAuth authentication that may require MFA.
     */
    public static class GoogleAuthResult {
        private final boolean mfaRequired;
        private final String tempToken;
        private final AuthService.TokenPair tokenPair;
        private final String profileImageUrl;

        private GoogleAuthResult(boolean mfaRequired, String tempToken, AuthService.TokenPair tokenPair, String profileImageUrl) {
            this.mfaRequired = mfaRequired;
            this.tempToken = tempToken;
            this.tokenPair = tokenPair;
            this.profileImageUrl = profileImageUrl;
        }

        public static GoogleAuthResult mfaRequired(String tempToken, String profileImageUrl) {
            return new GoogleAuthResult(true, tempToken, null, profileImageUrl);
        }

        public static GoogleAuthResult success(AuthService.TokenPair tokenPair) {
            return new GoogleAuthResult(false, null, tokenPair, tokenPair.getProfileImageUrl());
        }

        public boolean isMfaRequired() { return mfaRequired; }
        public String getTempToken() { return tempToken; }
        public AuthService.TokenPair getTokenPair() { return tokenPair; }
        public String getProfileImageUrl() { return profileImageUrl; }
    }

    @PostConstruct
    public void init() {
        if (googleClientId != null && !googleClientId.isEmpty()) {
            this.verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(),
                    GsonFactory.getDefaultInstance())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();
            logger.info("Google OAuth initialized with client ID: {}...",
                    googleClientId.substring(0, Math.min(10, googleClientId.length())));
        } else {
            logger.warn("Google OAuth client ID not configured. Google sign-in will be disabled.");
        }
    }

    /**
     * Authenticate user with Google ID token.
     * - If OAuth account exists, log in the user.
     * - If email exists but no OAuth account, link the OAuth account to existing user.
     * - If user doesn't exist, register a new user with OAuth account.
     *
     * @param idTokenString The Google ID token from frontend
     * @param deviceInfo    Device information for refresh token tracking
     * @return TokenPair containing access and refresh tokens
     */
    @Transactional
    public AuthService.TokenPair authenticateWithGoogle(String idTokenString, String deviceInfo) {
        GoogleAuthResult result = authenticateWithGoogleMfa(idTokenString, deviceInfo);
        if (result.isMfaRequired()) {
            // For backward compatibility, throw exception
            throw new OAuthAuthenticationException("MFA_REQUIRED:" + result.getTempToken());
        }
        return result.getTokenPair();
    }

    /**
     * Authenticate user with Google ID token with MFA support.
     * - If OAuth account exists, log in the user (MFA may be required).
     * - If email exists but no OAuth account, link the OAuth account to existing user.
     * - If user doesn't exist, register a new user with OAuth account.
     *
     * @param idTokenString The Google ID token from frontend
     * @param deviceInfo    Device information for refresh token tracking
     * @return GoogleAuthResult that may require MFA verification
     */
    @Transactional
    public GoogleAuthResult authenticateWithGoogleMfa(String idTokenString, String deviceInfo) {
        if (verifier == null) {
            throw new OAuthAuthenticationException("Google OAuth is not configured");
        }

        // Verify the Google ID token
        GoogleIdToken idToken = verifyGoogleToken(idTokenString);
        GoogleIdToken.Payload payload = idToken.getPayload();

        String googleUserId = payload.getSubject();
        String email = payload.getEmail();
        String name = (String) payload.get("name");
        String pictureUrl = (String) payload.get("picture");
        Boolean emailVerified = payload.getEmailVerified();

        if (email == null || email.isEmpty()) {
            throw new OAuthAuthenticationException("Email not provided by Google");
        }

        if (emailVerified != null && !emailVerified) {
            throw new OAuthAuthenticationException("Google email is not verified");
        }

        logger.info("Google OAuth: Processing authentication for email: {}", email);

        // Check if OAuth account already exists
        Optional<OAuthAccount> existingOAuthAccountOpt = oAuthAccountRepository
                .findByProviderAndProviderUserId(PROVIDER_GOOGLE, googleUserId);

        if (existingOAuthAccountOpt.isPresent()) {
            // User has logged in with Google before - update profile image URL and log them in
            OAuthAccount existingOAuthAccount = existingOAuthAccountOpt.get();
            User user = existingOAuthAccount.getUser();
            boolean updated = false;
            if (pictureUrl != null && !pictureUrl.isEmpty()) {
                if (existingOAuthAccount.getProfileImageUrl() == null ||
                        !existingOAuthAccount.getProfileImageUrl().equals(pictureUrl)) {
                    existingOAuthAccount.setProfileImageUrl(pictureUrl);
                    updated = true;
                }
            }
            if (updated) {
                oAuthAccountRepository.save(existingOAuthAccount);
                logger.info("Google OAuth: Updated profile image for OAuth account {}", existingOAuthAccount.getId());
            }

            logger.info("Google OAuth: Existing OAuth account found for user: {}", user.getUserId());

            // Check if user has MFA enabled
            if (Boolean.TRUE.equals(user.getMfaEnabled())) {
                String tempToken = tokenProvider.generateMfaTempToken(user);
                return GoogleAuthResult.mfaRequired(tempToken, pictureUrl);
            }

            return GoogleAuthResult.success(createTokenPairForUser(user, deviceInfo, pictureUrl));
        }

        // Check if a user with this email already exists (registered via username/password)
        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);

        if (existingUser.isPresent()) {
            // Link Google OAuth to existing user account and save profile image
            User user = existingUser.get();
            logger.info("Google OAuth: Linking Google account to existing user: {}", user.getUserId());
            linkOAuthAccount(user, googleUserId, pictureUrl);

            // Check if user has MFA enabled
            if (Boolean.TRUE.equals(user.getMfaEnabled())) {
                String tempToken = tokenProvider.generateMfaTempToken(user);
                return GoogleAuthResult.mfaRequired(tempToken, pictureUrl);
            }

            return GoogleAuthResult.success(createTokenPairForUser(user, deviceInfo, pictureUrl));
        }

        // Register new user with Google OAuth
        logger.info("Google OAuth: Registering new user with email: {}", email);
        User newUser = registerNewGoogleUser(email, name, googleUserId, pictureUrl);
        // New users don't have MFA enabled, so no MFA check needed
        return GoogleAuthResult.success(createTokenPairForUser(newUser, deviceInfo, pictureUrl));
    }

    /**
     * Verify Google ID token and return the parsed token.
     */
    private GoogleIdToken verifyGoogleToken(String idTokenString) {
        try {
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                throw new OAuthAuthenticationException("Invalid Google ID token");
            }
            return idToken;
        } catch (OAuthAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to verify Google ID token", e);
            throw new OAuthAuthenticationException("Failed to verify Google ID token: " + e.getMessage(), e);
        }
    }

    /**
     * Link OAuth account to existing user.
     */
    private void linkOAuthAccount(User user, String googleUserId, String profileImageUrl) {
        OAuthAccount oAuthAccount = new OAuthAccount();
        oAuthAccount.setUser(user);
        oAuthAccount.setProvider(PROVIDER_GOOGLE);
        oAuthAccount.setProviderUserId(googleUserId);
        oAuthAccount.setProfileImageUrl(profileImageUrl);
        oAuthAccountRepository.save(oAuthAccount);
        logger.info("Google OAuth: Linked Google account {} to user {}", googleUserId, user.getUserId());
    }

    /**
     * Register a new user from Google OAuth.
     * Creates user with password_hash = NULL (Google-only auth initially).
     */
    private User registerNewGoogleUser(String email, String name, String googleUserId, String profileImageUrl) {
        // Generate username from email (before @) or name
        String username = generateUniqueUsername(email, name);

        // Create user WITHOUT password - they'll use Google to log in
        // User can later set a password via /auth/set-password endpoint
        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        // password_hash is NULL for Google-only users
        user.setPasswordHash(null);

        User savedUser = userRepository.save(user);
        // Flush to ensure createdAt is populated by @CreationTimestamp
        userRepository.flush();

        logger.info("Google OAuth: Saved new user {} with createdAt {} (no password set)",
                savedUser.getUserId(), savedUser.getCreatedAt());

        // Create OAuth account link with profile image
        OAuthAccount oAuthAccount = new OAuthAccount();
        oAuthAccount.setUser(savedUser);
        oAuthAccount.setProvider(PROVIDER_GOOGLE);
        oAuthAccount.setProviderUserId(googleUserId);
        oAuthAccount.setProfileImageUrl(profileImageUrl);
        oAuthAccountRepository.save(oAuthAccount);

        // Assign default subscriptions (same as regular registration)
        logger.info("Google OAuth: Assigning default subscriptions to user {}", savedUser.getUserId());
        userSubscriptionService.assignDefaultSubscriptions(savedUser);

        logger.info("Google OAuth: Created new user {} with username {}", savedUser.getUserId(), username);

        return savedUser;
    }

    /**
     * Generate a unique username from email or name.
     */
    private String generateUniqueUsername(String email, String name) {
        // Try using the part before @ in email
        String baseUsername = email.split("@")[0]
                .replaceAll("[^a-zA-Z0-9_]", "_")
                .toLowerCase();

        // If name is provided and email part is too short, use name
        if (baseUsername.length() < 3 && name != null && !name.isEmpty()) {
            baseUsername = name.replaceAll("[^a-zA-Z0-9_]", "_").toLowerCase();
        }

        // Ensure minimum length
        if (baseUsername.length() < 3) {
            baseUsername = "user_" + baseUsername;
        }

        // Make it unique by appending numbers if needed
        String username = baseUsername;
        int suffix = 1;
        while (userRepository.existsByUsername(username)) {
            username = baseUsername + "_" + suffix;
            suffix++;
        }

        return username;
    }

    /**
     * Create token pair for authenticated user.
     */
    private AuthService.TokenPair createTokenPairForUser(User user, String deviceInfo, String profileImageUrl) {
        // Ensure default subscriptions exist
        List<UserSubscription> subscriptions = userSubscriptionService.ensureDefaultSubscriptions(user);
        user.setSubscriptions(subscriptions);

        // Generate access token
        String accessToken = tokenProvider.generateAccessToken(user);

        // Generate refresh token and store in DB
        String refreshToken = tokenProvider.generateRefreshToken();
        String refreshTokenHash = tokenProvider.hashRefreshToken(refreshToken);

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(user.getUserId().toString());
        refreshTokenEntity.setTokenHash(refreshTokenHash);
        refreshTokenEntity.setExpiresAt(java.time.LocalDateTime.now().plusSeconds(
                tokenProvider.getRefreshTokenExpirationMillis() / 1000));
        refreshTokenEntity.setCreatedAt(java.time.LocalDateTime.now());
        refreshTokenEntity.setLastUsedAt(java.time.LocalDateTime.now());
        refreshTokenEntity.setDeviceInfo(deviceInfo != null ?
                deviceInfo.substring(0, Math.min(deviceInfo.length(), 100)) : null);

        refreshTokenRepository.save(refreshTokenEntity);

        return new AuthService.TokenPair(accessToken, refreshToken, user, profileImageUrl);
    }

    /**
     * Check if Google OAuth is enabled/configured.
     */
    public boolean isGoogleOAuthEnabled() {
        return verifier != null;
    }
}

