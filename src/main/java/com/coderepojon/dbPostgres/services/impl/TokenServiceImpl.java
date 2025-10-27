package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.controllers.ForceLogoutController;
import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.services.TokenService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepo;
    private final UserRepository userRepo; // admin revocation

    public  TokenServiceImpl(TokenRepository tokenRepo, UserRepository userRepo) {
        this.tokenRepo = tokenRepo;
        this.userRepo = userRepo;
    }

    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt) {
        saveUserToken(user, jwtToken, type, expiresAt, null);
    }

    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt, Map<String, Object> metadata) {
        TokenEntity.TokenEntityBuilder builder = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .expiresAt(expiresAt)
                .revoked(false)
                .createdAt(Instant.now())
                .status("SUCCESS"); // Default status

        if (metadata != null) {
            builder.deviceId((String) metadata.getOrDefault("deviceId", null))
                    .device((String) metadata.getOrDefault("device", null))
                    .browser((String) metadata.getOrDefault("browser", null))
                    .os((String) metadata.getOrDefault("os", null))
                    .ipAddress((String) metadata.getOrDefault("ipAddress", null))
                    .country((String) metadata.getOrDefault("country", null))
                    .city((String) metadata.getOrDefault("city", null))
                    .sessionId((String) metadata.getOrDefault("sessionId", null));
        }

        tokenRepo.save(builder.build());
    }

    public void saveUserTokenWithMetadata(
            UserEntity user,
            String jwtToken,
            TokenType type,
            Instant expiresAt,
            String status,
            String deviceId,
            String device,
            String browser,
            String os,
            String ipAddress,
            String country,
            String city,
            String sessionId
    ) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status(status)
                .deviceId(deviceId)
                .device(device)
                .browser(browser)
                .os(os)
                .ipAddress(ipAddress)
                .country(country)
                .city(city)
                .sessionId(sessionId)
                .build();

        tokenRepo.save(token);
    }

    public boolean existAndValid(String token, UserEntity user) {
        return tokenRepo.findByUserAndTokenAndRevokedFalse(user, token)
                .map(t -> t.getExpiresAt().isAfter(Instant.now()))
                .orElse(false);
    }

    @Override
    public  void revokeAllUserTokens(UserEntity user) {
        tokenRepo.findAll().stream()
                .filter(t -> t.getUser().equals(user) && !t.isRevoked())
                .forEach(t -> {
                    t.setRevoked(true);
                    tokenRepo.save(t);
                });
    }

    @Override
    public boolean isTokenRevoked(String token) {
        return tokenRepo.findByToken(token)
                .map(TokenEntity::isRevoked)
                .orElse(true);// Treat missing tokens as revoke
    }

    @Override
    public void revokeToken(String token) {
        tokenRepo.findByToken(token).ifPresent(t -> {
            t.setRevoked(true);
            tokenRepo.save(t);
        });
    }

    @Override
    public void revokeTokensByUsername(String username) {
        UserEntity user = userRepo.fetchUserWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        List<TokenEntity> validTokens = tokenRepo.findAllByUserAndRevokedFalse(user);
        validTokens.forEach(t -> {
            t.setRevoked(true);
            t.setStatus("REVOKED");
        });

        tokenRepo.saveAll(validTokens);

        // Notify via SSE
        ForceLogoutController.sendLogoutEvent(username);
    }
}
