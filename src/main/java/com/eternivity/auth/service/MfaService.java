package com.eternivity.auth.service;

import com.eternivity.auth.dto.MfaSetupResponse;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.exception.MfaException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.repository.UserRepository;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for TOTP-based MFA operations using Google Authenticator.
 * Implements RFC 6238 TOTP with AES-GCM encryption for secret storage.
 */
@Service
public class MfaService {

    private static final Logger log = LoggerFactory.getLogger(MfaService.class);
    private static final String ISSUER = "Eternivity";
    private static final int SECRET_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int MAX_OTP_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator;
    private final QrGenerator qrGenerator;
    private final CodeVerifier codeVerifier;
    private final byte[] encryptionKey;

    // Rate limiting: track failed OTP attempts per user
    private final Map<UUID, OtpAttemptTracker> otpAttempts = new ConcurrentHashMap<>();

    public MfaService(UserRepository userRepository,
                      @Value("${mfa.encryption-key:}") String mfaEncryptionKey,
                      @Value("${jwt.secret:DefaultLocalKey12345678901234567}") String jwtSecret) {
        this.userRepository = userRepository;
        this.secretGenerator = new DefaultSecretGenerator(SECRET_LENGTH);
        this.qrGenerator = new ZxingPngQrGenerator();

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        // Allow ±1 time window (30s drift)
        ((DefaultCodeVerifier) this.codeVerifier).setTimePeriod(30);
        ((DefaultCodeVerifier) this.codeVerifier).setAllowedTimePeriodDiscrepancy(1);

        // Derive encryption key from mfaEncryptionKey or fall back to jwt.secret
        String keySource = (mfaEncryptionKey != null && !mfaEncryptionKey.isEmpty())
                ? mfaEncryptionKey : jwtSecret;
        this.encryptionKey = deriveKey(keySource);
    }

    /**
     * Generate a new TOTP setup for a user.
     * Returns secret and QR code but does NOT enable MFA yet.
     * MFA is only enabled after the first OTP verification.
     */
    public MfaSetupResponse generateMfaSetup(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (Boolean.TRUE.equals(user.getMfaEnabled())) {
            throw new MfaException("MFA is already enabled. Disable it first to reconfigure.");
        }

        // Generate new secret
        String secret = secretGenerator.generate();

        // Generate QR code data
        QrData qrData = new QrData.Builder()
                .label(user.getEmail())
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        String qrCodeUri = qrData.getUri();
        String qrCodeImage;

        try {
            byte[] imageData = qrGenerator.generate(qrData);
            qrCodeImage = "data:image/png;base64," + Base64.getEncoder().encodeToString(imageData);
        } catch (QrGenerationException e) {
            log.error("Failed to generate QR code", e);
            throw new MfaException("Failed to generate QR code");
        }

        return new MfaSetupResponse(secret, qrCodeUri, qrCodeImage);
    }

    /**
     * Verify OTP during MFA setup and enable MFA if valid.
     * This is the first OTP verification that enables MFA.
     */
    @Transactional
    public void verifyAndEnableMfa(UUID userId, String secret, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (Boolean.TRUE.equals(user.getMfaEnabled())) {
            throw new MfaException("MFA is already enabled");
        }

        // Rate limit check
        checkOtpRateLimit(userId);

        // Verify the OTP code
        if (!codeVerifier.isValidCode(secret, code)) {
            recordFailedOtpAttempt(userId);
            throw new MfaException("Invalid OTP code. Please try again.");
        }

        // Clear failed attempts on success
        otpAttempts.remove(userId);

        // Encrypt and store the secret
        String encryptedSecret = encrypt(secret);
        user.setMfaSecret(encryptedSecret);
        user.setMfaEnabled(true);
        user.setMfaEnabledAt(LocalDateTime.now());

        userRepository.save(user);
        log.info("MFA enabled for user: {}", userId);
    }

    /**
     * Verify OTP during login.
     * Returns true if the code is valid.
     */
    public boolean verifyOtp(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!Boolean.TRUE.equals(user.getMfaEnabled()) || user.getMfaSecret() == null) {
            throw new MfaException("MFA is not enabled for this user");
        }

        // Rate limit check
        checkOtpRateLimit(userId);

        // Decrypt the secret
        String secret = decrypt(user.getMfaSecret());

        // Verify the OTP code
        if (!codeVerifier.isValidCode(secret, code)) {
            recordFailedOtpAttempt(userId);
            return false;
        }

        // Clear failed attempts on success
        otpAttempts.remove(userId);
        return true;
    }

    /**
     * Disable MFA for a user.
     */
    @Transactional
    public void disableMfa(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!Boolean.TRUE.equals(user.getMfaEnabled())) {
            throw new MfaException("MFA is not enabled");
        }

        // Verify current OTP before disabling
        if (!verifyOtp(userId, code)) {
            throw new MfaException("Invalid OTP code. Cannot disable MFA.");
        }

        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        user.setMfaEnabledAt(null);

        userRepository.save(user);
        log.info("MFA disabled for user: {}", userId);
    }

    /**
     * Check if MFA is enabled for a user.
     */
    public boolean isMfaEnabled(UUID userId) {
        return userRepository.findById(userId)
                .map(user -> Boolean.TRUE.equals(user.getMfaEnabled()))
                .orElse(false);
    }

    // --- Encryption helpers ---

    private byte[] deriveKey(String source) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(source.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive encryption key", e);
        }
    }

    private String encrypt(String plaintext) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Combine IV and ciphertext
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new MfaException("Failed to encrypt MFA secret", e);
        }
    }

    private String decrypt(String encrypted) {
        try {
            byte[] combined = Base64.getDecoder().decode(encrypted);

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] ciphertext = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new MfaException("Failed to decrypt MFA secret", e);
        }
    }

    // --- Rate limiting helpers ---

    private void checkOtpRateLimit(UUID userId) {
        OtpAttemptTracker tracker = otpAttempts.get(userId);
        if (tracker != null) {
            if (tracker.isLocked()) {
                long remainingMs = tracker.getLockoutEndTime() - System.currentTimeMillis();
                long remainingMinutes = (remainingMs / 60000) + 1;
                throw new MfaException("Too many failed attempts. Please try again in " + remainingMinutes + " minutes.");
            }
        }
    }

    private void recordFailedOtpAttempt(UUID userId) {
        OtpAttemptTracker tracker = otpAttempts.computeIfAbsent(userId, k -> new OtpAttemptTracker());
        tracker.recordFailure();

        if (tracker.getAttempts() >= MAX_OTP_ATTEMPTS) {
            tracker.lock(System.currentTimeMillis() + LOCKOUT_DURATION_MS);
            log.warn("User {} locked out due to {} failed OTP attempts", userId, MAX_OTP_ATTEMPTS);
        }
    }

    /**
     * Inner class to track OTP attempts for rate limiting.
     */
    private static class OtpAttemptTracker {
        private int attempts = 0;
        private long lockoutEndTime = 0;

        public synchronized void recordFailure() {
            attempts++;
        }

        public synchronized int getAttempts() {
            return attempts;
        }

        public synchronized void lock(long endTime) {
            this.lockoutEndTime = endTime;
        }

        public synchronized boolean isLocked() {
            if (lockoutEndTime > 0 && System.currentTimeMillis() < lockoutEndTime) {
                return true;
            }
            // Reset if lockout expired
            if (lockoutEndTime > 0 && System.currentTimeMillis() >= lockoutEndTime) {
                reset();
            }
            return false;
        }

        public synchronized long getLockoutEndTime() {
            return lockoutEndTime;
        }

        public synchronized void reset() {
            attempts = 0;
            lockoutEndTime = 0;
        }
    }
}


