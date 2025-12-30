package com.eternivity.auth.controller;

import com.eternivity.auth.dto.LoginRequest;
import com.eternivity.auth.dto.RegisterRequest;
import com.eternivity.auth.dto.UserInfoResponse;
import com.eternivity.auth.dto.PasswordChangeRequest;
import com.eternivity.auth.exception.InvalidCredentialsException;
import com.eternivity.auth.exception.UserAlreadyExistsException;
import com.eternivity.auth.exception.UserNotFoundException;
import com.eternivity.auth.service.AuthService;
import com.eternivity.auth.service.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CookieService cookieService;

    @Value("${app.allowed-redirect-domains:.eternivity.com}")
    private String allowedRedirectDomains;

    public AuthController(AuthService authService, CookieService cookieService) {
        this.authService = authService;
        this.cookieService = cookieService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        try {
            String deviceInfo = getDeviceInfo(httpRequest);
            AuthService.TokenPair tokenPair = authService.register(request, deviceInfo);

            // Set HttpOnly cookies for SSO
            cookieService.addAccessTokenCookie(response, tokenPair.getAccessToken());
            cookieService.addRefreshTokenCookie(response, tokenPair.getRefreshToken());

            // Handle redirect if provided
            if (isValidRedirectUri(redirectUri)) {
                response.sendRedirect(redirectUri);
                return null;
            }

            return ResponseEntity.status(HttpStatus.CREATED).body(new AuthSuccessResponse(
                    "Registration successful",
                    tokenPair.getUser().getUsername(),
                    tokenPair.getUser().getEmail()
            ));
        } catch (UserAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Redirect failed"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        try {
            String deviceInfo = getDeviceInfo(httpRequest);
            AuthService.TokenPair tokenPair = authService.login(request, deviceInfo);

            // Set HttpOnly cookies for SSO
            cookieService.addAccessTokenCookie(response, tokenPair.getAccessToken());
            cookieService.addRefreshTokenCookie(response, tokenPair.getRefreshToken());

            // Handle redirect if provided
            if (isValidRedirectUri(redirectUri)) {
                response.sendRedirect(redirectUri);
                return null;
            }

            return ResponseEntity.ok(new AuthSuccessResponse(
                    "Login successful",
                    tokenPair.getUser().getUsername(),
                    tokenPair.getUser().getEmail()
            ));
        } catch (InvalidCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Redirect failed"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        try {
            // Get refresh token from cookie
            String refreshToken = getRefreshTokenFromCookie(httpRequest);
            if (refreshToken == null || refreshToken.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorResponse("Refresh token not found"));
            }

            String deviceInfo = getDeviceInfo(httpRequest);
            AuthService.TokenPair tokenPair = authService.refreshTokens(refreshToken, deviceInfo);

            // Set new HttpOnly cookies (token rotation)
            cookieService.addAccessTokenCookie(response, tokenPair.getAccessToken());
            cookieService.addRefreshTokenCookie(response, tokenPair.getRefreshToken());

            return ResponseEntity.ok(new MessageResponse("Tokens refreshed successfully"));
        } catch (InvalidCredentialsException | UserNotFoundException e) {
            // Clear cookies on invalid refresh token
            cookieService.clearAuthCookies(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "global", defaultValue = "false") boolean globalLogout,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        try {
            // Get refresh token from cookie to revoke it
            String refreshToken = getRefreshTokenFromCookie(httpRequest);

            if (globalLogout) {
                // Global logout - revoke all refresh tokens for the user
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication != null && authentication.getPrincipal() instanceof UUID) {
                    UUID userId = (UUID) authentication.getPrincipal();
                    authService.logoutAll(userId);
                }
            } else {
                // Single session logout
                authService.logout(refreshToken);
            }

            // Clear cookies
            cookieService.clearAuthCookies(response);

            // Handle redirect if provided
            if (isValidRedirectUri(redirectUri)) {
                response.sendRedirect(redirectUri);
                return null;
            }

            return ResponseEntity.ok(new MessageResponse("Logout successful"));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Redirect failed"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UUID userId = (UUID) authentication.getPrincipal();
            
            UserInfoResponse userInfoResponse = authService.getCurrentUser(userId);
            return ResponseEntity.ok(userInfoResponse);
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping("/password-reset")
    public ResponseEntity<?> changePassword(
            @RequestBody PasswordChangeRequest request,
            HttpServletResponse response) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UUID userId = (UUID) authentication.getPrincipal();
            authService.changePassword(userId, request.getOldPassword(), request.getNewPassword());

            // Clear cookies as all refresh tokens are revoked on password change
            cookieService.clearAuthCookies(response);

            return ResponseEntity.ok(new MessageResponse("Password changed successfully. Please login again."));
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(e.getMessage()));
        } catch (InvalidCredentialsException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(e.getMessage()));
        }
    }

    /**
     * Extract device info from User-Agent header for token tracking
     */
    private String getDeviceInfo(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    /**
     * Get refresh token from HttpOnly cookie
     */
    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieService.REFRESH_TOKEN_COOKIE.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Validate redirect URI to prevent open redirect attacks
     * Only allows redirects to *.eternivity.com subdomains
     */
    private boolean isValidRedirectUri(String redirectUri) {
        if (redirectUri == null || redirectUri.isEmpty()) {
            return false;
        }

        try {
            URI uri = URI.create(redirectUri);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }

            // Parse allowed domains from config
            String[] allowedDomains = allowedRedirectDomains.split(",");
            for (String domain : allowedDomains) {
                String trimmedDomain = domain.trim();
                if (trimmedDomain.startsWith(".")) {
                    // Wildcard domain like .eternivity.com
                    if (host.endsWith(trimmedDomain) || host.equals(trimmedDomain.substring(1))) {
                        return true;
                    }
                } else {
                    // Exact domain match
                    if (host.equals(trimmedDomain)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    // Response DTOs
    public static class AuthSuccessResponse {
        private String message;
        private String username;
        private String email;

        public AuthSuccessResponse(String message, String username, String email) {
            this.message = message;
            this.username = username;
            this.email = email;
        }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

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

    public static class MessageResponse {
        private String message;

        public MessageResponse(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }
}
