package com.eternivity.auth.service;

import com.eternivity.auth.dto.AuthResponse;
import com.eternivity.auth.dto.LoginRequest;
import com.eternivity.auth.dto.RegisterRequest;
import com.eternivity.auth.dto.UserInfoResponse;
import com.eternivity.auth.entity.RefreshToken;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import com.eternivity.auth.exception.InvalidCredentialsException;
import com.eternivity.auth.exception.UserAlreadyExistsException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.repository.RefreshTokenRepository;
import com.eternivity.auth.repository.UserRepository;
import com.eternivity.auth.repository.UserSubscriptionRepository;
import com.eternivity.auth.repository.OAuthAccountRepository;
import com.eternivity.auth.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserSubscriptionRepository userSubscriptionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OAuthAccountRepository oAuthAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final UserSubscriptionService userSubscriptionService;

    public AuthService(UserRepository userRepository,
                       UserSubscriptionRepository userSubscriptionRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       OAuthAccountRepository oAuthAccountRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider tokenProvider,
                       UserSubscriptionService userSubscriptionService) {
        this.userRepository = userRepository;
        this.userSubscriptionRepository = userSubscriptionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.oAuthAccountRepository = oAuthAccountRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.userSubscriptionService = userSubscriptionService;
    }

    /**
     * Result containing both access and refresh tokens
     */
    public static class TokenPair {
        private final String accessToken;
        private final String refreshToken;
        private final User user;
        private final String profileImageUrl; // optional, used for OAuth logins

        public TokenPair(String accessToken, String refreshToken, User user) {
            this(accessToken, refreshToken, user, null);
        }

        public TokenPair(String accessToken, String refreshToken, User user, String profileImageUrl) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.user = user;
            this.profileImageUrl = profileImageUrl;
        }

        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public User getUser() { return user; }
        public String getProfileImageUrl() { return profileImageUrl; }
    }

    @Transactional
    public TokenPair register(RegisterRequest request, String deviceInfo) {
        // Check if username already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username is already taken");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email is already in use");
        }

        // Create new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));

        User savedUser = userRepository.save(user);

        // Assign default free subscriptions for all available services
        userSubscriptionService.assignDefaultSubscriptions(savedUser);

        // Fetch subscriptions for JWT token generation
        List<UserSubscription> subscriptions = userSubscriptionRepository.findByUser_UserId(savedUser.getUserId());
        savedUser.setSubscriptions(subscriptions);

        // Generate tokens
        return createTokenPair(savedUser, deviceInfo);
    }

    @Transactional
    public TokenPair login(LoginRequest request, String deviceInfo) {
        String identifier = request.getIdentifier().trim();

        User user;
        if (identifier.contains("@")) {
            // Treat as email (case-insensitive)
            user = userRepository.findByEmailIgnoreCase(identifier)
                    .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));
        } else {
            // Treat as username
            user = userRepository.findByUsername(identifier)
                    .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));
        }

        // Check if user has a password set (Google-only users have NULL password_hash)
        if (user.getPasswordHash() == null || user.getPasswordHash().isEmpty()) {
            throw new InvalidCredentialsException("No password set. Please use Google login or set a password first.");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid username/email or password");
        }

        // Ensure default subscriptions exist for existing users (assigns missing ones)
        List<UserSubscription> subscriptions = userSubscriptionService.ensureDefaultSubscriptions(user);
        user.setSubscriptions(subscriptions);

        // Generate tokens
        return createTokenPair(user, deviceInfo);
    }

    @Transactional
    public TokenPair refreshTokens(String refreshTokenValue, String deviceInfo) {
        // Hash the incoming refresh token to compare with stored hash
        String tokenHash = tokenProvider.hashRefreshToken(refreshTokenValue);

        // Find the valid refresh token
        RefreshToken storedToken = refreshTokenRepository
                .findValidByTokenHash(tokenHash, LocalDateTime.now())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid or expired refresh token"));

        // Get the user
        User user = userRepository.findById(UUID.fromString(storedToken.getUserId()))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Ensure default subscriptions exist for users (assigns missing ones)
        List<UserSubscription> subscriptions = userSubscriptionService.ensureDefaultSubscriptions(user);
        user.setSubscriptions(subscriptions);

        // Revoke the old refresh token (rotate)
        storedToken.setRevokedAt(LocalDateTime.now());
        refreshTokenRepository.save(storedToken);

        // Generate new token pair
        return createTokenPair(user, deviceInfo);
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        if (refreshTokenValue != null && !refreshTokenValue.isEmpty()) {
            String tokenHash = tokenProvider.hashRefreshToken(refreshTokenValue);
            refreshTokenRepository.revokeByTokenHash(tokenHash, LocalDateTime.now());
        }
    }

    @Transactional
    public void logoutAll(UUID userId) {
        refreshTokenRepository.revokeAllByUserId(userId.toString(), LocalDateTime.now());
    }

    @Transactional
    public UserInfoResponse getCurrentUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Ensure default subscriptions exist for users (assigns missing ones)
        List<UserSubscription> subscriptions = userSubscriptionService.ensureDefaultSubscriptions(user);

        Map<String, UserInfoResponse.ServiceInfo> services = new HashMap<>();
        for (UserSubscription subscription : subscriptions) {
            UserInfoResponse.ServiceInfo serviceInfo = new UserInfoResponse.ServiceInfo(
                    subscription.getPlan(),
                    subscription.getStatus(),
                    subscription.getEndDate()
            );
            services.put(subscription.getServiceCode(), serviceInfo);
        }

        // Try to fetch profile image URL from OAuth accounts (prefer Google)
        String profileImageUrl = null;
        List<String> authProviders = new java.util.ArrayList<>();

        try {
            Optional<com.eternivity.auth.entity.OAuthAccount> oauthOpt =
                    oAuthAccountRepository.findByUserAndProvider(user, "google");

            if (oauthOpt.isPresent()) {
                profileImageUrl = oauthOpt.get().getProfileImageUrl();
                authProviders.add("GOOGLE");
            }
        } catch (Exception e) {
            // ignore and continue without profile image
        }

        // Check if user has a local password set
        boolean hasPassword = user.getPasswordHash() != null && !user.getPasswordHash().isEmpty();
        if (hasPassword) {
            authProviders.add(0, "LOCAL"); // Add LOCAL first if present
        }

        return new UserInfoResponse(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                services,
                profileImageUrl,
                hasPassword,
                authProviders
        );
    }

    /**
     * Set password for a user who doesn't have one (Google-only users).
     * This allows Google users to enable local login.
     *
     * @param userId The user's ID
     * @param newPassword The new password to set
     * @throws InvalidCredentialsException if user already has a password set or password is too short
     */
    @Transactional
    public void setPassword(UUID userId, String newPassword) {
        // Validate password length
        if (newPassword == null || newPassword.length() < 8) {
            throw new InvalidCredentialsException("Password must be at least 8 characters long");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Only allow setting password if no password exists
        if (user.getPasswordHash() != null && !user.getPasswordHash().isEmpty()) {
            throw new InvalidCredentialsException("Password already set. Use change password instead.");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // No need to revoke tokens - user is just enabling local login
    }

    @Transactional
    public void changePassword(UUID userId, String oldPassword, String newPassword) {
        // Validate password length
        if (newPassword == null || newPassword.length() < 8) {
            throw new InvalidCredentialsException("Password must be at least 8 characters long");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Check if user has a password to change
        if (user.getPasswordHash() == null || user.getPasswordHash().isEmpty()) {
            throw new InvalidCredentialsException("No password set. Use set password instead.");
        }

        if (!passwordEncoder.matches(oldPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException("Old password is incorrect");
        }

        // Check if new password is same as old password
        if (passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException("New password must be different from your current password");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all refresh tokens on password change for security
        refreshTokenRepository.revokeAllByUserId(userId.toString(), LocalDateTime.now());
    }

    /**
     * Create a new token pair (access + refresh) and store refresh token hash in DB
     */
    private TokenPair createTokenPair(User user, String deviceInfo) {
        // Generate access token
        String accessToken = tokenProvider.generateAccessToken(user);

        // Generate refresh token
        String refreshToken = tokenProvider.generateRefreshToken();
        String refreshTokenHash = tokenProvider.hashRefreshToken(refreshToken);

        // Store refresh token in DB
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(user.getUserId().toString());
        refreshTokenEntity.setTokenHash(refreshTokenHash);
        refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusSeconds(
                tokenProvider.getRefreshTokenExpirationMillis() / 1000));
        refreshTokenEntity.setCreatedAt(LocalDateTime.now());
        refreshTokenEntity.setLastUsedAt(LocalDateTime.now());
        refreshTokenEntity.setDeviceInfo(deviceInfo != null ?
                deviceInfo.substring(0, Math.min(deviceInfo.length(), 100)) : null);

        refreshTokenRepository.save(refreshTokenEntity);

        // For non-OAuth flows we don't have a profile image URL
        return new TokenPair(accessToken, refreshToken, user, null);
    }

    /**
     * @deprecated Use register(RegisterRequest, String) instead
     */
    @Deprecated
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        TokenPair tokenPair = register(request, null);
        return new AuthResponse(tokenPair.getAccessToken(),
                tokenPair.getUser().getUsername(),
                tokenPair.getUser().getEmail());
    }

    /**
     * @deprecated Use login(LoginRequest, String) instead
     */
    @Deprecated
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        TokenPair tokenPair = login(request, null);
        return new AuthResponse(tokenPair.getAccessToken(),
                tokenPair.getUser().getUsername(),
                tokenPair.getUser().getEmail());
    }
}
