package com.devsecops.vulncheckerbackend.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

class SecurityConfigTest {

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() throws Exception {
        securityConfig = new SecurityConfig();
        Field field = SecurityConfig.class.getDeclaredField("allowedOriginsRaw");
        field.setAccessible(true);
        field.set(securityConfig, "http://localhost,http://localhost:5173");
    }

    @Test
    void passwordEncoder_createsBCryptInstance() {
        BCryptPasswordEncoder encoder = securityConfig.passwordEncoder();
        assertNotNull(encoder);
        String encoded = encoder.encode("test123");
        assertTrue(encoder.matches("test123", encoded));
    }

    @Test
    void corsConfigurationSource_hasDefaults() {
        UrlBasedCorsConfigurationSource source = (UrlBasedCorsConfigurationSource) securityConfig.corsConfigurationSource();
        assertNotNull(source);

        CorsConfiguration config = source.getCorsConfigurations().get("/**");

        assertNotNull(config);
        assertTrue(config.getAllowedOriginPatterns().containsAll(
                java.util.List.of("http://localhost", "http://localhost:5173")));
        assertTrue(config.getAllowedMethods().contains("GET"));
        assertTrue(config.getAllowedMethods().contains("POST"));
        assertTrue(config.getAllowedMethods().contains("OPTIONS"));
        assertTrue(config.getAllowedHeaders().contains("Authorization"));
        assertTrue(config.getAllowedHeaders().contains("Content-Type"));
    }
}
