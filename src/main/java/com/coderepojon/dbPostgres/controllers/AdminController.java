package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.services.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "http://localhost:4200")
public class AdminController {

    private final TokenService tokenService;
    private final UserRepository userRepo;

    public AdminController(TokenService tokenService, UserRepository userRepo) {
        this.tokenService = tokenService;
        this.userRepo = userRepo;
    }

    @PostMapping("/revoke/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> revokeUserTokens(@PathVariable String username) {
        UserEntity user = userRepo.fetchUserWithRoles(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        tokenService.revokeTokensByUsername(username);
        Map<String, String> response = new HashMap<>();
        response.put("message", "Revoked all tokens for user: " + username);
        return ResponseEntity.ok(response);
    }
}
