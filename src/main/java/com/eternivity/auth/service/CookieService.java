package com.eternivity.auth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CookieService {

    public static final String ACCESS_TOKEN_COOKIE = "access_token";
    public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    @Value("${jwt.access-token.expiration:900}")
    private int accessTokenExpirationSeconds;

    @Value("${jwt.refresh-token.expiration:604800}")
    private int refreshTokenExpirationSeconds;

    @Value("${app.cookie.domain:.eternivity.com}")
    private String cookieDomain;

    @Value("${app.cookie.secure:true}")
    private boolean secureCookie;

    /**
     * Creates and adds access token cookie to response
     */
    public void addAccessTokenCookie(HttpServletResponse response, String accessToken) {
        Cookie cookie = createCookie(ACCESS_TOKEN_COOKIE, accessToken, accessTokenExpirationSeconds);
        response.addCookie(cookie);
    }

    /**
     * Creates and adds refresh token cookie to response
     */
    public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = createCookie(REFRESH_TOKEN_COOKIE, refreshToken, refreshTokenExpirationSeconds);
        response.addCookie(cookie);
    }

    /**
     * Clears both access and refresh token cookies
     */
    public void clearAuthCookies(HttpServletResponse response) {
        Cookie accessCookie = createCookie(ACCESS_TOKEN_COOKIE, "", 0);
        Cookie refreshCookie = createCookie(REFRESH_TOKEN_COOKIE, "", 0);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }

    /**
     * Creates a secure HttpOnly cookie with SameSite for cross-subdomain SSO
     */
    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        // Only set domain if it's not empty (empty means localhost)
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        // SameSite=None requires Secure=true, use Lax for non-secure (localhost)
        if (secureCookie) {
            cookie.setAttribute("SameSite", "None");
        } else {
            cookie.setAttribute("SameSite", "Lax");
        }
        return cookie;
    }
}

