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
        System.out.println(">>> Loaded user: " + userEntity.getUsername());
        System.out.println(">>> Role size: " + userEntity.getRoles().size());

        if(userEntity == null || !userEntity.getPassword().equals(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        List<String> roleNames = userEntity.getRoles()
                .stream()
                .map(RoleEntity::getName)
                .peek(r -> System.out.println(">>> Role: " +r))
                .collect(Collectors.toList());

        System.out.println(">>> Token generation for user: " + userEntity.getUsername());
        System.out.println(">>> Roles fetched: " + userEntity.getRoles()
                .stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toList()));
        System.out.println(">>> Role before token: " + roleNames);

        String token = jwtUtil.generateToken(username, roleNames);

        userEntity.setToken(token);
        userEntity.setSession(UUID.randomUUID().toString());
        userRepo.save(userEntity);

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("session", userEntity.getSession());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing or invalid Authorization header");
        }

        String oldToken = authHeader.substring(7);
        try{
            // Validate existing token
//            if (jwtUtil.isTokenExpired(oldToken)) {
            // allow refreshing slightly expired tokens (within 30 seconds of expiry)
            long expMillis = jwtUtil.getClaims(oldToken).getExpiration().getTime();
            if (System.currentTimeMillis() - expMillis > 30_000) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expired - please log in again");
            }

            String username = jwtUtil.extractUsername(oldToken);
            UserEntity userEntity = userRepo.fetchUserWithRoles(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            //Generate a fresh token with same roles
            List<String> roles = userEntity.getRoles()
                    .stream()
                    .map(RoleEntity::getName)
                    .collect(Collectors.toList());

            String newToken = jwtUtil.generateToken(username, roles);

            //Optionally update stored token/session
            userEntity.setToken(newToken);
            userRepo.save(userEntity);

            Map<String, Object> response = new HashMap<>();
            response.put("token", newToken);
            response.put("session", userEntity.getSession());

            return ResponseEntity.ok(response);

        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }
}
