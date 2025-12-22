package com.eternivity.auth.service;

import com.eternivity.auth.dto.AuthResponse;
import com.eternivity.auth.dto.LoginRequest;
import com.eternivity.auth.dto.RegisterRequest;
import com.eternivity.auth.dto.UserInfoResponse;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import com.eternivity.auth.exception.InvalidCredentialsException;
import com.eternivity.auth.exception.UserAlreadyExistsException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.repository.UserRepository;
import com.eternivity.auth.repository.UserSubscriptionRepository;
import com.eternivity.auth.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserSubscriptionRepository userSubscriptionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public AuthService(UserRepository userRepository,
                       UserSubscriptionRepository userSubscriptionRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.userSubscriptionRepository = userSubscriptionRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
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

        // Generate JWT token
        String token = tokenProvider.generateToken(savedUser);

        return new AuthResponse(token, savedUser.getUsername(), savedUser.getEmail());
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
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

        // Generate JWT token
        String token = tokenProvider.generateToken(user);

        return new AuthResponse(token, user.getUsername(), user.getEmail());
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
}
