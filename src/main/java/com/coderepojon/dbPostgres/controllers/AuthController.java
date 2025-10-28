package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.LoginRequestDTO;
import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.*;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.security.JwtUtil;
import com.coderepojon.dbPostgres.services.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Autowired
    private final UserRepository userRepo;
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;
    private final TokenRepository tokenRepo;

    public AuthController(UserRepository userRepo, JwtUtil jwtUtil, TokenService tokenService, TokenRepository tokenRepo) {
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
        this.tokenService = tokenService;
        this.tokenRepo = tokenRepo;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginData, HttpServletRequest request) {
        String username = loginData.getUsername();
        String password = loginData.getPassword();

        UserEntity userEntity = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if(!userEntity.getPassword().equals(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        String session_Id = UUID.randomUUID().toString();
        userEntity.setSession(session_Id);
        userRepo.save(userEntity);
//        userEntity = userRepo.saveAndFlush(userEntity); // ensure persistence

        List<String> roleNames = userEntity.getRoles()
                .stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toList());

        // Generate JWT
        String accessToken = jwtUtil.generateAccessToken(username, roleNames);
        Date accessExp  = jwtUtil.getClaims(accessToken).getExpiration();// use getClaim directly
        String refreshToken = jwtUtil.generateRefreshToken(username);
        Date refreshExp  = jwtUtil.getClaims(refreshToken).getExpiration();// use getClaim directly

        // Extract metadata from request
        Map<String, Object> meta = loginData.getMetadata();
        String deviceId = meta != null ? (String) meta.getOrDefault("deviceId", null) : null;
        String device = meta != null ? (String) meta.getOrDefault("device", null) : null;
        String browser = meta != null ? (String) meta.getOrDefault("browser", null) : null;
        String os = meta != null ? (String) meta.getOrDefault("os", null) : null;
        String ipAddress = meta != null ? (String) meta.getOrDefault("ipAddress", null) : request.getRemoteAddr();
        String country = meta != null ? (String) meta.getOrDefault("country", null) : null;
        String city = meta != null ? (String) meta.getOrDefault("city", null) : null;

        String userAgentRaw = request.getHeader("User-Agent");
        String loginMethod = "PASSWORD"; // or OAUTH, MFA, etc.
        Boolean mfaUsed = false;
        String mfaType = null;

        TokenMetadata metadata = TokenMetadata.builder()
                .deviceId(deviceId)
                .device(device)
                .browser(browser)
                .os(os)
                .ipAddress(ipAddress)
                .country(country)
                .city(city)
                .sessionId(session_Id)
                .userAgentRaw(userAgentRaw)
                .loginMethod(loginMethod)
                .mfaUsed(mfaUsed)
                .mfaType(mfaType)
                .success(true)
                // Fields below reserved for future use (set to null for now)
                .failureReason(null)
                .latitude(null)
                .longitude(null)
                .timezone(null)
                .issuer(null)
                .clientId(null)
                .riskScore(null)
                .isNewDevice(null)
                .isVpnOrProxy(null)
                .networkProvider(null)
                .logoutAt(null)
                .revokedReason(null)
                .build();

//        tokenService.saveUserTokenWithMetadata(
//                userEntity,
//                accessToken,
//                TokenType.ACCESS,
//                accessExp .toInstant(),
//                "SUCCESS",
//                deviceId,
//                device,
//                browser,
//                os,
//                ipAddress,
//                country,
//                city,
//                session_Id
//        );
//
//        tokenService.saveUserTokenWithMetadata(
//                userEntity,
//                refreshToken,
//                TokenType.REFRESH,
//                refreshExp.toInstant(),
//                "SUCCESS",
//                deviceId,
//                device,
//                browser,
//                os,
//                ipAddress,
//                country,
//                city,
//                session_Id
//        );

        tokenService.saveUserTokenWithMetadata(userEntity, accessToken, TokenType.ACCESS, accessExp.toInstant(), "ACTIVE", metadata);
        tokenService.saveUserTokenWithMetadata(userEntity, refreshToken, TokenType.REFRESH, refreshExp.toInstant(), "ACTIVE", metadata);
        // --- Prepare response ---
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        response.put("session", userEntity.getSession());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String accessToken = request.get("accessToken");

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

            //Generate a fresh token with same roles
            List<String> roles = userEntity.getRoles()
                    .stream()
                    .map(RoleEntity::getName)
                    .collect(Collectors.toList());

            String newAccessToken = jwtUtil.generateAccessToken(refreshUsername, roles);
            Date newAccessExpiry = jwtUtil.getClaims(newAccessToken).getExpiration();

            String newRefreshToken = jwtUtil.generateRefreshToken(refreshUsername);
            Date newRefreshExpiry = jwtUtil.getClaims(newRefreshToken).getExpiration();

            // Reuse old metadata for new tokens
            TokenMetadata reusedMeta = TokenMetadata.builder()
                    .deviceId(oldMeta.getDeviceId())
                    .device(oldMeta.getDevice())
                    .browser(oldMeta.getBrowser())
                    .os(oldMeta.getOs())
                    .ipAddress(oldMeta.getIpAddress())
                    .country(oldMeta.getCountry())
                    .city(oldMeta.getCity())
                    .sessionId(oldMeta.getSessionId())
                    .build();

            tokenService.saveUserToken(userEntity, newAccessToken, TokenType.ACCESS, newAccessExpiry.toInstant(), reusedMeta);
            tokenService.saveUserToken(userEntity, newRefreshToken, TokenType.REFRESH, newRefreshExpiry.toInstant(), reusedMeta);

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
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        try {
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);

            UserEntity user = userRepo.fetchUserWithRoles(username)
                            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            tokenService.revokeAllUserTokens(user);

            user.setSession(null);
            userRepo.save(user);

            return ResponseEntity.ok("Logged out successfully");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed");
        }
    }

    @PostMapping("/logoutSession")
    public ResponseEntity<?> logoutSession(@RequestHeader("Authorization") String authHeader, @RequestParam String sessionId) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        sessionId = sessionId.replace("\"", "");

        String token = authHeader.substring(7);
        String username = jwtUtil.extractUsername(token);

        UserEntity user = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Revoke all tokens with this sessionId
        tokenService.revokeTokensBySession(user, sessionId);

        // If the session being revoked is the current one, also clear user's session field
        if (sessionId.equals(user.getSession())) {
            user.setSession(null);
            userRepo.save(user);
        }

        return ResponseEntity.ok("Session logged out successfully");
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
