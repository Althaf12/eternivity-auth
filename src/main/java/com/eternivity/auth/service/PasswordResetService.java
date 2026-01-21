package com.eternivity.auth.service;

import com.eternivity.auth.entity.PasswordResetToken;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.exception.BadRequestException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.exception.InvalidTokenException;
import com.eternivity.auth.repository.PasswordResetTokenRepository;
import com.eternivity.auth.repository.UserRepository;
import com.eternivity.auth.exception.MailSendingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final JavaMailSender mailSender; // required
    private final PasswordEncoder passwordEncoder;

    @Value("${app.password-reset.token-expiry-minutes}")
    private int tokenExpiryMinutes;

    @Value("${app.password-reset.frontend-url}")
    private String frontendResetUrl;

    // default from address when spring.mail.username is not set (local/dev)
    @Value("${spring.mail.username:no-reply@eternivity.com}")
    private String fromEmail;

    public PasswordResetService(UserRepository userRepository,
                                PasswordResetTokenRepository tokenRepository,
                                JavaMailSender mailSender,
                                PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailSender = mailSender;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Initiates the password reset flow:
     * 1. Validates user exists by email
     * 2. Invalidates any existing tokens
     * 3. Generates a new reset token
     * 4. Stores hashed token in DB
     * 5. Sends email with reset link
     */
    @Transactional
    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmailIgnoreCase(email.trim())
                .orElseThrow(() -> new UserNotFoundException("No account found with email: " + email));

        String userIdStr = user.getUserId().toString();

        // Invalidate any existing tokens for this user
        tokenRepository.invalidateAllTokensForUser(userIdStr, LocalDateTime.now());

        // Generate a secure random token
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);

        // Create and save the token entity
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId(userIdStr);
        resetToken.setTokenHash(tokenHash);
        resetToken.setCreatedAt(LocalDateTime.now());
        resetToken.setExpiresAt(LocalDateTime.now().plusMinutes(tokenExpiryMinutes));

        tokenRepository.save(resetToken);

        // Send email with reset link
        sendPasswordResetEmail(user.getEmail(), user.getUsername(), rawToken);

        log.info("Password reset email flow initiated for user: {}", user.getEmail());
    }

    /**
     * Validates the reset token and sets new password:
     * 1. Finds valid token by hash
     * 2. Validates new password is different from existing
     * 3. Updates user password
     * 4. Marks token as used
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        // Validate password length
        if (newPassword == null || newPassword.length() < 8) {
            throw new BadRequestException("Password must be at least 8 characters long");
        }

        String tokenHash = hashToken(rawToken);

        PasswordResetToken resetToken = tokenRepository
                .findValidTokenByHash(tokenHash, LocalDateTime.now())
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired reset token"));

        // Get the user
        User user = userRepository.findById(java.util.UUID.fromString(resetToken.getUserId()))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Check if new password is same as existing password
        if (user.getPasswordHash() != null && passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new BadRequestException("New password must be different from your current password");
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Mark token as used
        resetToken.setUsedAt(LocalDateTime.now());
        tokenRepository.save(resetToken);

        log.info("Password reset successfully for user: {}", user.getEmail());
    }

    /**
     * Generates a cryptographically secure random token
     */
    private String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Hashes the token using SHA-256 for secure and consistent storage/lookup
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Sends the password reset email
     */
    private void sendPasswordResetEmail(String toEmail, String username, String token) {
        String resetLink = frontendResetUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject("Eternivity - Password Reset Request");
        message.setText(buildEmailBody(username, resetLink));

        try {
            mailSender.send(message);
            log.info("Password reset email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
            throw new MailSendingException("Failed to send password reset email. Please try again later.", e);
        }
    }

    private String buildEmailBody(String username, String resetLink) {
        return String.format("""
            Hello %s,
            
            You requested to reset your password for your Eternivity account.
            
            Click the link below to reset your password:
            %s
            
            This link will expire in %d minutes.
            
            If you did not request this password reset, please ignore this email or contact support if you have concerns.
            
            Best regards,
            The Eternivity Team
            """, username, resetLink, tokenExpiryMinutes);
    }
}

