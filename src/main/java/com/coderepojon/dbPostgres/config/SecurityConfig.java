package com.coderepojon.dbPostgres.config;

import com.coderepojon.dbPostgres.security.JwtAuthenticationFilter;
import com.coderepojon.dbPostgres.security.JwtUtil;
import com.coderepojon.dbPostgres.security.UserDetailsServiceImpl;
import com.coderepojon.dbPostgres.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableMethodSecurity // Allows @PreAuthorize, @PostAuthorize, @RolesAllowed
@Profile("!test") // Only active when NOT in 'test' profile
public class SecurityConfig {

    @Autowired
    public UserDetailsServiceImpl userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    public TokenService tokenService;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService, tokenService);
    }

    /**
     * CORS Config (Frontend: Angular Local Dev)
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4200")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedMethods("*")
                        .allowCredentials(true);
            }
        };
    }

    /**
     * Main Security Filter Chain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth

                        // Public endpoints
                        .requestMatchers("/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/refresh").permitAll()
                        .requestMatchers("/api/sse/subscribe/**").permitAll()

                        // Images
                        .requestMatchers("/static/avatars/**").permitAll()

                        // Admin-only REST endpoints
                        .requestMatchers(HttpMethod.POST, "/authors/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/authors/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/authors/**").hasRole("ADMIN")

                        // Everyone authenticated can read
                        .requestMatchers(HttpMethod.GET, "/authors/**").authenticated()

                        // Everything else must be authenticated
                        .anyRequest().authenticated()
                )
                // JWT filter BEFORE UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
