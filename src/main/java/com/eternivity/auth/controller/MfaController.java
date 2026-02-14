package com.eternivity.auth.controller;

import com.eternivity.auth.dto.MfaResponse;
import com.eternivity.auth.dto.MfaSetupResponse;
import com.eternivity.auth.dto.MfaVerifyRequest;
import com.eternivity.auth.entity.RefreshToken;
import com.eternivity.auth.entity.User;
import com.eternivity.auth.exception.MfaException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.repository.RefreshTokenRepository;
import com.eternivity.auth.repository.UserRepository;
import com.eternivity.auth.security.JwtTokenProvider;
import com.eternivity.auth.service.CookieService;
import com.eternivity.auth.service.MfaService;
import com.eternivity.auth.service.UserSubscriptionService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Controller for MFA (Multi-Factor Authentication) operations.
 * Implements TOTP-based MFA using Google Authenticator.
 */
@RestController
@RequestMapping("/api/auth/mfa")
public class MfaController {

    private static final Logger log = LoggerFactory.getLogger(MfaController.class);

    private final MfaService mfaService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider tokenProvider;
    private final CookieService cookieService;
    private final UserSubscriptionService userSubscriptionService;

    public MfaController(MfaService mfaService,
                         UserRepository userRepository,
                         RefreshTokenRepository refreshTokenRepository,
                         JwtTokenProvider tokenProvider,
                         CookieService cookieService,
                         UserSubscriptionService userSubscriptionService) {
        this.mfaService = mfaService;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenProvider = tokenProvider;
        this.cookieService = cookieService;
        this.userSubscriptionService = userSubscriptionService;
    }

    /**
     * Get MFA status for the authenticated user.
     */
    @GetMapping("/status")
    public ResponseEntity<?> getMfaStatus() {
        try {
            UUID userId = getAuthenticatedUserId();
            boolean enabled = mfaService.isMfaEnabled(userId);
            return ResponseEntity.ok(MfaResponse.success(
                    enabled ? "MFA is enabled" : "MFA is not enabled",
                    enabled
            ));
        } catch (Exception e) {
            log.error("Error getting MFA status", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(MfaResponse.error("Failed to get MFA status"));
        }
    }

    /**
     * Initiate MFA setup - generates secret and QR code.
     * User must be authenticated to call this endpoint.
     */
    @PostMapping("/setup")
    public ResponseEntity<?> setupMfa() {
        try {
            UUID userId = getAuthenticatedUserId();
            MfaSetupResponse response = mfaService.generateMfaSetup(userId);
            return ResponseEntity.ok(response);
        } catch (MfaException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Error setting up MFA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(MfaResponse.error("Failed to setup MFA"));
        }
    }

    /**
     * Verify OTP and enable MFA.
     * Called after scanning QR code with Google Authenticator.
     */
    @PostMapping("/enable")
    public ResponseEntity<?> enableMfa(@Valid @RequestBody MfaVerifyRequest request) {
        try {
            UUID userId = getAuthenticatedUserId();

            if (request.getSecret() == null || request.getSecret().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(MfaResponse.error("Secret is required for MFA setup"));
            }

            mfaService.verifyAndEnableMfa(userId, request.getSecret(), request.getCode());
            return ResponseEntity.ok(MfaResponse.success("MFA enabled successfully", true));
        } catch (MfaException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Error enabling MFA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(MfaResponse.error("Failed to enable MFA"));
        }
    }

    /**
     * Disable MFA.
     * Requires current OTP for verification.
     */
    @PostMapping("/disable")
    public ResponseEntity<?> disableMfa(@Valid @RequestBody MfaVerifyRequest request) {
        try {
            UUID userId = getAuthenticatedUserId();
            mfaService.disableMfa(userId, request.getCode());
            return ResponseEntity.ok(MfaResponse.success("MFA disabled successfully", false));
        } catch (MfaException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Error disabling MFA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(MfaResponse.error("Failed to disable MFA"));
        }
    }

    /**
     * Verify OTP - handles both login flow and enable flow.
     *
     * For LOGIN FLOW (MFA_REQUIRED during login):
     *   - Requires: tempToken + code
     *   - Exchanges temp token + OTP for full access token
     *
     * For ENABLE FLOW (enabling MFA from profile):
     *   - Requires: secret + code (user must be authenticated)
     *   - Verifies OTP and enables MFA for the user
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyMfa(
            @Valid @RequestBody MfaVerifyRequest request,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            HttpServletResponse response) {
        try {
            // Check if this is an ENABLE flow (has secret, user is authenticated)
            if (request.getSecret() != null && !request.getSecret().isEmpty()) {
                // ENABLE FLOW - user is enabling MFA from profile
                return handleEnableMfa(request);
            }

            // LOGIN FLOW - user is verifying MFA during login
            String tempToken = request.getTempToken();
            if (tempToken == null || tempToken.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorResponse("Temporary token is required for login verification, or secret is required for MFA setup"));
            }

            // Validate temp token
            UUID userId = tokenProvider.validateMfaTempToken(tempToken);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Invalid or expired temporary token"));
            }

            // Verify OTP
            boolean valid = mfaService.verifyOtp(userId, request.getCode());
            if (!valid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Invalid OTP code"));
            }

            // Get user and generate full tokens
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UserNotFoundException("User not found"));

            // Ensure subscriptions are loaded
            var subscriptions = userSubscriptionService.ensureDefaultSubscriptions(user);
            user.setSubscriptions(subscriptions);

            // Generate access token with mfa=true
            String accessToken = tokenProvider.generateAccessToken(user, true);
            String refreshTokenValue = tokenProvider.generateRefreshToken();
            String refreshTokenHash = tokenProvider.hashRefreshToken(refreshTokenValue);

            // Store refresh token in DB
            RefreshToken refreshTokenEntity = new RefreshToken();
            refreshTokenEntity.setUserId(user.getUserId().toString());
            refreshTokenEntity.setTokenHash(refreshTokenHash);
            refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusSeconds(
                    tokenProvider.getRefreshTokenExpirationMillis() / 1000));
            refreshTokenEntity.setCreatedAt(LocalDateTime.now());
            refreshTokenEntity.setLastUsedAt(LocalDateTime.now());
            refreshTokenRepository.save(refreshTokenEntity);

            // Set cookies
            cookieService.addAccessTokenCookie(response, accessToken);
            cookieService.addRefreshTokenCookie(response, refreshTokenValue);

            return ResponseEntity.ok(new AuthController.AuthSuccessResponse(
                    "MFA verification successful",
                    user.getUsername(),
                    user.getEmail(),
                    null // Profile image URL not needed here
            ));

        } catch (MfaException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("Error verifying MFA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Failed to verify MFA"));
        }
    }

    private UUID getAuthenticatedUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getPrincipal() == null) {
            throw new SecurityException("Not authenticated");
        }
        return (UUID) authentication.getPrincipal();
    }

    /**
     * Handle enable MFA flow - user is enabling MFA from profile page.
     * Requires user to be authenticated and provides secret + code.
     */
    private ResponseEntity<?> handleEnableMfa(MfaVerifyRequest request) {
        try {
            UUID userId = getAuthenticatedUserId();

            mfaService.verifyAndEnableMfa(userId, request.getSecret(), request.getCode());
            return ResponseEntity.ok(MfaResponse.success("MFA enabled successfully", true));
        } catch (MfaException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(MfaResponse.error(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(MfaResponse.error("Authentication required to enable MFA"));
        } catch (Exception e) {
            log.error("Error enabling MFA", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(MfaResponse.error("Failed to enable MFA"));
        }
    }

    // Response DTOs
    public static class ErrorResponse {
        private String message;

        public ErrorResponse(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}




