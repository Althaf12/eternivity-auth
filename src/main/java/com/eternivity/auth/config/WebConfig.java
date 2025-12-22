package com.eternivity.auth.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.beans.factory.annotation.Value;

import java.util.Arrays;

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
}
