package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.services.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "http://localhost:4200")
public class AdminController {

    private final TokenService tokenService;

    public AdminController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/revoke/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> revokeUserTokens(@PathVariable String username) {
        tokenService.revokeTokensByUsername(username);
        return ResponseEntity.ok("Revoked all active tokens for user: " + username);
    }
}
