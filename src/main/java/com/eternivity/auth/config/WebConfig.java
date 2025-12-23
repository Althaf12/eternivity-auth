package com.eternivity.auth.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    // Inject the CSV list of allowed origin patterns from application.properties
    @SuppressWarnings("unused") // injected via Spring @Value
    @Value("${app.cors.allowed-origins:}")
    private String allowedOriginsProperty;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Parse the CSV property (comma-separated), trim whitespace and filter empty entries
        String[] patterns = Arrays.stream(allowedOriginsProperty.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);

        // Configure CORS mapping for API endpoints. Only apply allowed origin patterns when provided.
        var registration = registry.addMapping("/api/**")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);

        if (patterns.length > 0) {
            registration.allowedOriginPatterns(patterns);
        }
    }

    // Provide a CorsConfigurationSource bean so Spring Security's CORS support (http.cors(...)) can use the same settings.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        List<String> patterns = Arrays.stream(allowedOriginsProperty.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        if (!patterns.isEmpty()) {
            // Use allowed origin patterns to support wildcards like http://localhost:*
            config.setAllowedOriginPatterns(patterns);
        }

        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Register for all paths; WebMvc mapping still restricts /api/** but security needs the source available
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
