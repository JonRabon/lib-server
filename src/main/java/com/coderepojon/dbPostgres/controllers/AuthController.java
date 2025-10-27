package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.LoginRequestDTO;
import com.coderepojon.dbPostgres.domain.entities.RoleEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.security.JwtUtil;
import com.coderepojon.dbPostgres.services.TokenService;
import jakarta.transaction.Transactional;
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
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginData) {
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
        String refreshToken = jwtUtil.generateRefreshToken(username);

        // Extract metadata from request
        Map<String, Object> meta = loginData.getMetadata();
        String deviceId = meta != null ? (String) meta.getOrDefault("deviceId", null) : null;
        String device = meta != null ? (String) meta.getOrDefault("device", null) : null;
        String browser = meta != null ? (String) meta.getOrDefault("browser", null) : null;
        String os = meta != null ? (String) meta.getOrDefault("os", null) : null;
        String ipAddress = meta != null ? (String) meta.getOrDefault("ipAddress", null) : null;
        String country = meta != null ? (String) meta.getOrDefault("country", null) : null;
        String city = meta != null ? (String) meta.getOrDefault("city", null) : null;
        String sessionId = session_Id;

        // Revoke old tokens first
        tokenService.revokeAllUserTokens(userEntity);

        // Save new ones
        Date expiration = jwtUtil.getClaims(accessToken).getExpiration();// use getClaim directly

        tokenService.saveUserTokenWithMetadata(
                userEntity,
                accessToken,
                TokenType.ACCESS,
                expiration.toInstant(),
                "SUCCESS",
                deviceId,
                device,
                browser,
                os,
                ipAddress,
                country,
                city,
                sessionId
        );

        tokenService.saveUserTokenWithMetadata(
                userEntity,
                refreshToken,
                TokenType.REFRESH,
                expiration.toInstant(),
                "SUCCESS",
                deviceId,
                device,
                browser,
                os,
                ipAddress,
                country,
                city,
                sessionId
        );

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

            // Extract username from refresh token
            String refreshUsername = jwtUtil.extractUsername(refreshToken);
            // Extract username from old access token
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

            // Get metadata from existing refresh token
            TokenEntity oldRefresh = tokenRepo.findByToken(refreshToken).orElseThrow();

            //Generate a fresh token with same roles
            List<String> roles = userEntity.getRoles()
                    .stream()
                    .map(RoleEntity::getName)
                    .collect(Collectors.toList());

            // Revoke this refresh token before issuing a new one
            tokenService.revokeToken(accessToken);
            tokenService.revokeToken(refreshToken);

            String newAccessToken = jwtUtil.generateAccessToken(refreshUsername, roles);
            String newRefreshToken = jwtUtil.generateRefreshToken(refreshUsername);

            Date newAccessExpiry = jwtUtil.getClaims(newAccessToken).getExpiration();
            Date newRefreshExpiry = jwtUtil.getClaims(newRefreshToken).getExpiration();

            // 🧠 Reuse old metadata for new tokens
            Map<String, Object> metadata = Map.of(
                    "deviceId", oldRefresh.getDeviceId(),
                    "device", oldRefresh.getDevice(),
                    "browser", oldRefresh.getBrowser(),
                    "os", oldRefresh.getOs(),
                    "ipAddress", oldRefresh.getIpAddress(),
                    "country", oldRefresh.getCountry(),
                    "city", oldRefresh.getCity(),
                    "sessionId", oldRefresh.getSessionId()
            );

            tokenService.saveUserToken(userEntity, newAccessToken, TokenType.ACCESS, newAccessExpiry.toInstant(), metadata);
            tokenService.saveUserToken(userEntity, newRefreshToken, TokenType.REFRESH, newRefreshExpiry.toInstant(), metadata);

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
}
