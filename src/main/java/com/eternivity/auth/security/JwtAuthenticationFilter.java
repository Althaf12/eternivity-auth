package com.eternivity.auth.security;

import com.eternivity.auth.service.CookieService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenProvider tokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String requestUri = request.getRequestURI();
            String method = request.getMethod();
            log.debug("Processing request: {} {}", method, requestUri);

            // Guard: if SecurityContext already has an authenticated non-anonymous principal, skip processing
            Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
            if (existingAuth != null && existingAuth.isAuthenticated() &&
                    !(existingAuth instanceof AnonymousAuthenticationToken)) {
                log.debug("Existing non-anonymous authentication found, skipping JWT processing");
                filterChain.doFilter(request, response);
                return;
            }

            String jwt = getJwtFromRequest(request);
            log.debug("JWT from request: {}", jwt != null ? "present (length=" + jwt.length() + ")" : "null");

            if (StringUtils.hasText(jwt)) {
                boolean valid = tokenProvider.validateToken(jwt);
                log.debug("JWT validation result: {}", valid);

                if (valid) {
                    UUID userId = tokenProvider.getUserIdFromToken(jwt);
                    String username = tokenProvider.getUsernameFromToken(jwt);
                    log.debug("JWT valid for userId={}, username={}", userId, username);

                    // Extract roles/authorities from token claims, if present
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    try {
                        Claims claims = tokenProvider.getAllClaimsFromToken(jwt);
                        Object rolesObj = claims.get("roles");

                        if (rolesObj instanceof String rolesStr) {
                            authorities = Arrays.stream(rolesStr.split(","))
                                    .map(String::trim)
                                    .filter(s -> !s.isEmpty())
                                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                                    .map(SimpleGrantedAuthority::new)
                                    .collect(Collectors.toList());
                        } else if (rolesObj instanceof List) {
                            @SuppressWarnings("unchecked")
                            List<Object> list = (List<Object>) rolesObj;
                            authorities = list.stream()
                                    .filter(Objects::nonNull)
                                    .map(Object::toString)
                                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                                    .map(SimpleGrantedAuthority::new)
                                    .collect(Collectors.toList());
                        }
                    } catch (Exception ex) {
                        log.debug("Failed to extract roles from JWT claims, will fall back to default role", ex);
                    }

                    if (authorities.isEmpty()) {
                        authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                    }

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userId, null, authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.debug("JWT authentication set for userId={}", userId);
                } else {
                    log.debug("JWT validation failed for request: {} {}", method, requestUri);
                }
            } else {
                log.debug("No JWT found in request: {} {}", method, requestUri);
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        // First, try to get JWT from HttpOnly cookie (primary method for SSO)
        String jwtFromCookie = getJwtFromCookie(request);
        if (StringUtils.hasText(jwtFromCookie)) {
            return jwtFromCookie;
        }

        // Fallback to Authorization header for backward compatibility and API clients
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private String getJwtFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (CookieService.ACCESS_TOKEN_COOKIE.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
