package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.entities.RoleEntity;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Autowired
    private final UserRepository userRepo;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepo, JwtUtil jwtUtil) {
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {
        String username = loginData.get("username");
        String password = loginData.get("password");

        UserEntity userEntity = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        //Logging
//        System.out.println(">>> Loaded user: " + userEntity.getUsername());
//        System.out.println(">>> Role size: " + userEntity.getRoles().size());

        if(userEntity == null || !userEntity.getPassword().equals(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        List<String> roleNames = userEntity.getRoles()
                .stream()
                .map(RoleEntity::getName)
                .peek(r -> System.out.println(">>> Role: " +r))
                .collect(Collectors.toList());

//        System.out.println(">>> Token generation for user: " + userEntity.getUsername());
//        System.out.println(">>> Roles fetched: " + userEntity.getRoles()
//                .stream()
//                .map(RoleEntity::getName)
//                .collect(Collectors.toList()));
//        System.out.println(">>> Role before token: " + roleNames);

        String accessToken = jwtUtil.generateAccessToken(username, roleNames);
        String refreshToken = jwtUtil.generateRefreshToken(username);

        userEntity.setToken(accessToken);
        userEntity.setRefreshToken(refreshToken);
        userEntity.setSession(UUID.randomUUID().toString());
        userRepo.save(userEntity);

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
            // Validate existing token
//            if (jwtUtil.isTokenExpired(oldToken)) {
            // allow refreshing slightly expired tokens (within 30 seconds of expiry)
//            long expMillis = jwtUtil.getClaims(oldToken).getExpiration().getTime();
//            if (System.currentTimeMillis() - expMillis > 30_000) {

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

            if (!refreshToken.equals(userEntity.getRefreshToken())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token does not match server record");
            }

            //Generate a fresh token with same roles
            List<String> roles = userEntity.getRoles()
                    .stream()
                    .map(RoleEntity::getName)
                    .collect(Collectors.toList());

            String newAccessToken = jwtUtil.generateAccessToken(refreshUsername, roles);

            //Optionally update stored token/session
            String newRefreshToken = jwtUtil.generateRefreshToken(refreshUsername);
            userEntity.setRefreshToken(newRefreshToken);
            userEntity.setToken(newAccessToken);
            userRepo.save(userEntity);

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

            userRepo.fetchUserWithRoles(username).ifPresent(user -> {
                //Invalidate tokens and session
                user.setToken(null);
                user.setRefreshToken(null);
                user.setSession(null);
                userRepo.save(user);
            });

            return ResponseEntity.ok("Logged out successfully");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed");
        }
    }
}
