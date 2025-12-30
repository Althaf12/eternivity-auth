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
import com.eternivity.auth.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserSubscriptionRepository userSubscriptionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public AuthService(UserRepository userRepository,
                       UserSubscriptionRepository userSubscriptionRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.userSubscriptionRepository = userSubscriptionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
    }

    /**
     * Result containing both access and refresh tokens
     */
    public static class TokenPair {
        private final String accessToken;
        private final String refreshToken;
        private final User user;

        public TokenPair(String accessToken, String refreshToken, User user) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.user = user;
        }

        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public User getUser() { return user; }
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

        // Generate tokens
        return createTokenPair(savedUser, deviceInfo);
    }

    @Transactional
    public TokenPair login(LoginRequest request, String deviceInfo) {
        // Find user by username
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        // Fetch subscriptions for JWT token generation
        List<UserSubscription> subscriptions = userSubscriptionRepository.findByUser_UserId(user.getUserId());
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

        // Fetch subscriptions for JWT token generation
        List<UserSubscription> subscriptions = userSubscriptionRepository.findByUser_UserId(user.getUserId());
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

    @Transactional(readOnly = true)
    public UserInfoResponse getCurrentUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        List<UserSubscription> subscriptions = userSubscriptionRepository.findByUser_UserId(userId);

        Map<String, UserInfoResponse.ServiceInfo> services = new HashMap<>();
        for (UserSubscription subscription : subscriptions) {
            UserInfoResponse.ServiceInfo serviceInfo = new UserInfoResponse.ServiceInfo(
                    subscription.getPlan(),
                    subscription.getStatus()
            );
            services.put(subscription.getServiceCode(), serviceInfo);
        }

        return new UserInfoResponse(user.getUserId(), user.getUsername(), user.getEmail(), services);
    }

    @Transactional
    public void changePassword(UUID userId, String oldPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(oldPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException("Old password is incorrect");
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

        return new TokenPair(accessToken, refreshToken, user);
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
