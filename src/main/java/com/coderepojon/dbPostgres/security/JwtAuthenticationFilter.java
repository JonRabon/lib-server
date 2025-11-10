package com.coderepojon.dbPostgres.security;

import com.coderepojon.dbPostgres.services.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final TokenService tokenService;
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService, TokenService tokenService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);
        String username;

        try {
            username = jwtUtil.extractUsername(jwt);
        } catch (Exception e) {
            // Invalid token → reject
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Unauthorized\"}");
            return;
        }

        // Reject refresh tokens on all endpoints except refresh
        boolean isRefreshToken = jwtUtil.isRefreshToken(jwt);
        boolean isRefreshEndpoint = request.getRequestURI().contains("/api/auth/refresh");

        // Reject refresh tokens on normal API endpoints
        if (isRefreshToken && !isRefreshEndpoint) {
            // If someone tries to use a refresh token on a normal API route
            log.warn("Blocked refresh token used on API endpoint: {}", request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Unauthorized\"}");
            return;
        }

        // Only proceed if username exists and auth not set
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Check token validity AND DB revocation
            boolean validJwt = jwtUtil.isTokenValid(jwt, userDetails);
            boolean notRevoked = tokenService == null || !tokenService.isTokenRevoked(jwt);

            // Only proceed if username exists and auth not set
            if(jwtUtil.isTokenValid(jwt, userDetails) && (tokenService == null || !tokenService.isTokenRevoked(jwt))) {
                // If token is valid and not revoked, set authentication
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Unauthorized\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
