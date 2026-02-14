package com.eternivity.auth.config;

import com.eternivity.auth.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS - uses the CorsConfigurationSource bean from WebConfig
            .cors(Customizer.withDefaults())
            // CSRF protection is disabled because this is a stateless REST API using JWT tokens
            // stored in HttpOnly cookies with SameSite=None for cross-subdomain SSO.
            // CSRF is mitigated by: HttpOnly cookies, SameSite attribute, and domain validation.
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Allow preflight OPTIONS requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Public auth endpoints
                .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/google").permitAll()
                // Password reset endpoints (public - no auth required)
                .requestMatchers("/api/auth/forgot-password", "/api/auth/reset-password").permitAll()
                // MFA verification during login (public - uses temp token, not regular auth)
                .requestMatchers("/api/auth/mfa/verify").permitAll()
                // JWT key endpoint for downstream services (should be secured in production via network/API gateway)
                .requestMatchers("/api/auth/jwk").permitAll()
                // MFA management endpoints (require authentication: setup, enable, disable, status)
                .requestMatchers("/api/auth/mfa/setup", "/api/auth/mfa/enable", "/api/auth/mfa/disable", "/api/auth/mfa/status").authenticated()
                // Protected endpoints
                .requestMatchers("/api/auth/me", "/api/auth/password-reset", "/api/auth/logout", "/api/auth/set-password").authenticated()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
