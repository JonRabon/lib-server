package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.LoginRequestDTO;
import com.coderepojon.dbPostgres.domain.dto.RefreshRequestDTO;
import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.*;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.security.JwtUtil;
import com.coderepojon.dbPostgres.services.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Autowired
    private final UserRepository userRepo;
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;
    private final TokenRepository tokenRepo;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepo,
                          JwtUtil jwtUtil,
                          TokenService tokenService,
                          TokenRepository tokenRepo,
                          PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
        this.tokenService = tokenService;
        this.tokenRepo = tokenRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginData, HttpServletRequest request) {
        String username = loginData.getUsername();
        String password = loginData.getPassword();

        UserEntity userEntity = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

//        if (!userEntity.getPassword().equals(password)) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
//        }

        if (!passwordEncoder.matches(password, userEntity.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        String session_Id = UUID.randomUUID().toString();
        userEntity.setSession(session_Id);
        userRepo.save(userEntity);

        List<String> roleNames = userEntity.getRoles()
                .stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toList());

        // Generate JWT
        String accessToken = jwtUtil.generateAccessToken(username, roleNames);
        Date accessExp  = jwtUtil.getClaims(accessToken).getExpiration();// use getClaim directly
        String refreshToken = jwtUtil.generateRefreshToken(username);
        Date refreshExp  = jwtUtil.getClaims(refreshToken).getExpiration();// use getClaim directly

        Map<String, Object> metadataMap = loginData.getMetadata() != null
                ? new HashMap<>(loginData.getMetadata())
                : new HashMap<>();

        // log.info("loginData: >>> " + loginData.toString());
        if (loginData.getClientId() != null) {
            metadataMap.put("clientId", loginData.getClientId());
            metadataMap.put("sessionId", session_Id);
            //log.info("single entry points");
        } else {
            // For multiple entry points, Auto-Detect Client ID Server-Side
            // log.info("multiple entry points 1");
            String userAgentRaw = metadataMap != null ? (String) metadataMap.getOrDefault("userAgentRaw", null) : null;
            if (userAgentRaw != null ) {
                String clientId = request.getHeader("X-Client-Id"); // e.g., set by frontend
                if (clientId == null && userAgentRaw != null && userAgentRaw.contains("Android")) {
                    metadataMap.put("clientId", "mobile-android");
                }
            }
        }

        TokenMetadata metadata = mapDtoFromLoginRequest(metadataMap, null, null);

        // Save access and refresh tokens — server enriches metadata inside service
        tokenService.saveUserTokenWithMetadata(userEntity, accessToken, TokenType.ACCESS, accessExp.toInstant(), "ACTIVE", metadata, request);
        tokenService.saveUserTokenWithMetadata(userEntity, refreshToken, TokenType.REFRESH, refreshExp.toInstant(), "ACTIVE", metadata, request);

        // --- Prepare response ---
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        response.put("session", userEntity.getSession());

        return ResponseEntity.ok(response);
    }

    private TokenMetadata mapDtoFromLoginRequest(Map<String, Object> metadata, String accessToken, String refreshToken) {
        if (metadata == null) {
            return null;
        }

        boolean isRefreshFlow = (refreshToken != null && accessToken != null);

        TokenMetadata.TokenMetadataBuilder builder = TokenMetadata.builder()
                // Common fields for both login & refresh
                .networkProvider((String) metadata.getOrDefault("networkProvider", null))
                .ipAddress((String) metadata.getOrDefault("ipAddress", null))
                .country((String) metadata.getOrDefault("country", null))
                .city((String) metadata.getOrDefault("city", null))
                .clientId((String) metadata.getOrDefault("clientId", null))
                .isVpnOrProxy(parseBoolean(metadata.get("isVpnOrProxy")))
                .issuer((String) metadata.getOrDefault("issuer", null))
                .latitude(parseDouble(metadata.get("latitude")))
                .longitude(parseDouble(metadata.get("longitude")))
                .riskScore(parseDouble(metadata.get("riskScore")))
                .success(parseBoolean(metadata.get("success")))
                .timezone((String) metadata.getOrDefault("timezone", null));

        // If it’s a login flow, include full metadata
        if (!isRefreshFlow) {
            builder
                    .device((String) metadata.getOrDefault("device", null))
                    .deviceId((String) metadata.getOrDefault("deviceId", null))
                    .browser((String) metadata.getOrDefault("browser", null))
                    .os((String) metadata.getOrDefault("os", null))
                    .isNewDevice(parseBoolean(metadata.get("isNewDevice")))
                    .loginMethod((String) metadata.getOrDefault("loginMethod", null))
                    .mfaUsed(parseBoolean(metadata.get("mfaUsed")))
                    .mfaType((String) metadata.getOrDefault("mfaType", null))
                    .userAgentRaw((String) metadata.getOrDefault("userAgentRaw", null))
                    .sessionId((String) metadata.getOrDefault("sessionId", null))
                    .failureReason((String) metadata.getOrDefault("failureReason", null))
                    .revokedReason((String) metadata.getOrDefault("revokedReason", null));
        }

        return builder.build();
    }

    /**
     * Utility to safely parse any object to Boolean.
     * Handles cases where JSON sends "true"/"false" as strings or booleans.
     */
    private Boolean parseBoolean(Object value) {
        if (value == null) return null;
        if (value instanceof Boolean) return (Boolean) value;
        if (value instanceof String) return Boolean.valueOf((String) value);
        return null;
    }

    /**
     * Utility to safely parse any object to Float.
     */
    private Float parseFloat(Object value) {
        if (value == null) return null;
        if (value instanceof Number) return ((Number) value).floatValue();
        if (value instanceof String s && !s.isEmpty()) {
            try {
                return Float.parseFloat(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Utility to safely parse any object to Double.
     */
    private Double parseDouble(Object value) {
        if (value == null) return null;
        if (value instanceof Number) return ((Number) value).doubleValue();
        if (value instanceof String s && !s.isEmpty()) {
            try {
                return Double.parseDouble(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshRequestDTO request, HttpServletRequest httpRequest) {
        String refreshToken = request.getRefreshToken();
        String accessToken = request.getAccessToken();

        if (refreshToken == null || accessToken == null) {
            return ResponseEntity.badRequest().body("Both refreshToken and accessToken are required");
        }

        try{

            if (jwtUtil.isTokenExpired(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token - please log in again");
            }

            // Extract username from old refresh token and access token
            String refreshUsername = jwtUtil.extractUsername(refreshToken);
            String accessUsername = jwtUtil.extractUsername(accessToken);

            //Both must belong to the same user
            if (!refreshUsername.equals(accessUsername)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token user mismatch");
            }

            // Validate user from DB
            UserEntity userEntity = userRepo.fetchUserWithRoles(refreshUsername)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            //Validate that the token exists and is not revoked
            if (!tokenService.existAndValid(refreshToken, userEntity)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Refresh token does not exist or has been revoked");
            }

            // Fetch old refresh token entity (and its metadata)
            TokenEntity oldRefresh = tokenRepo.findByToken(refreshToken).orElseThrow();
            TokenMetadataEntity oldMeta = oldRefresh.getMetadata();

            // Revoke this refresh token before issuing a new one
            tokenService.revokeToken(accessToken);
            tokenService.revokeToken(refreshToken);

            // Generate a fresh token with same roles
            List<String> roles = userEntity.getRoles()
                    .stream()
                    .map(RoleEntity::getName)
                    .collect(Collectors.toList());

            String newAccessToken = jwtUtil.generateAccessToken(refreshUsername, roles);
            Date newAccessExpiry = jwtUtil.getClaims(newAccessToken).getExpiration();

            String newRefreshToken = jwtUtil.generateRefreshToken(refreshUsername);
            Date newRefreshExpiry = jwtUtil.getClaims(newRefreshToken).getExpiration();

            // log.info("loginRequest: >>> " + request.toString());
            Map<String, Object> metadataMap = request.getMetadata() != null
                    ? new HashMap<>(request.getMetadata())
                    : new HashMap<>();

            TokenMetadata metadata = mapDtoFromLoginRequest(metadataMap, request.getAccessToken(), request.getRefreshToken());
            metadata.setDeviceId(oldMeta.getDeviceId());
            metadata.setDevice(oldMeta.getDevice());
            metadata.setBrowser(oldMeta.getBrowser());
            metadata.setOs(oldMeta.getOs());
            metadata.setIsNewDevice(oldMeta.getIsNewDevice());
            metadata.setLoginMethod(oldMeta.getLoginMethod());
            metadata.setMfaUsed(oldMeta.getMfaUsed());
            metadata.setMfaType(oldMeta.getMfaType());
            metadata.setUserAgentRaw(oldMeta.getUserAgentRaw());
            metadata.setSessionId(oldMeta.getSessionId());

            // Save access and refresh tokens — server enriches metadata inside service
            tokenService.saveUserTokenWithMetadata(userEntity, newAccessToken, TokenType.ACCESS, newAccessExpiry.toInstant(), "ACTIVE", metadata, httpRequest);
            tokenService.saveUserTokenWithMetadata(userEntity, newRefreshToken, TokenType.REFRESH, newRefreshExpiry.toInstant(), "ACTIVE", metadata, httpRequest);

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            response.put("refreshToken", newRefreshToken);
            response.put("session", userEntity.getSession());

            return ResponseEntity.ok(response);

        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Could not refresh token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) Map<String, String> body
    ) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        try {
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);

            String reason = body != null ? body.getOrDefault("logoutReason", "Normal") : "Undefined";
            UserEntity user = userRepo.fetchUserWithRoles(username)
                            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            tokenService.revokeAllUserTokens(user, reason);

            user.setSession(null);
            userRepo.save(user);

            return ResponseEntity.ok("Logged out successfully");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed");
        }
    }

    @PostMapping("/logoutSession")
    public ResponseEntity<?> logoutSession(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam String sessionId,
            @RequestBody(required = false) Map<String, String> body
    ) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }
        // log.info("logoutRequest: >>> " + authHeader.toString());

        sessionId = sessionId.replace("\"", "");
        String token = authHeader.substring(7);
        String username = jwtUtil.extractUsername(token);

        String reason = body != null ? body.getOrDefault("logoutReason", "Normal") : "Undefined";
        // log.info("Logout request by {} | Session={} | Reason={}", username, sessionId, reason);

        UserEntity user = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // log.info(user.getUsername() + "---" + sessionId);
        // Revoke all tokens with this sessionId
        tokenService.revokeTokensBySession(user, sessionId, reason);

        // If the session being revoked is the current one, also clear user's session field
        if (sessionId.equals(user.getSession())) {
            user.setSession(null);
            userRepo.save(user);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("status", 200);
        response.put("message", "Session logged out successfully");
        response.put("sessionId", sessionId);
        response.put("username", username);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logoutAllExceptCurrent")
    public ResponseEntity<?> logoutAllExceptCurrent(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);
        String username = jwtUtil.extractUsername(token);

        UserEntity user = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String currentSession = user.getSession();

        // Revoke all tokens except current session
        tokenService.revokeAllExceptSession(user, currentSession);

        return ResponseEntity.ok("All other sessions revoked successfully");
    }
}
