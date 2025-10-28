package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.controllers.ForceLogoutController;
import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenMetadataEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.TokenMetadataRepository;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.services.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepo;
    private final TokenMetadataRepository metadataRepo;
    private final UserRepository userRepo; // admin revocation

    // -------------------------------
    // Existence / Validity Check
    // -------------------------------
    @Override
    public boolean existAndValid(String token, UserEntity user) {
        return tokenRepo.findByTokenAndUser(token, user)
                .filter(t -> !t.isRevoked() && t.getExpiresAt().isAfter(Instant.now()))
                .isPresent();
    }

    // -------------------------------
    // Save Token (Basic)
    // -------------------------------
    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status("ACTIVE")
                .build();

        tokenRepo.save(token);
    }

    // -------------------------------
    // Save Token (with simple metadata map)
    // -------------------------------
    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt, TokenMetadata metadata) {
        String sessionId = metadata != null ? (String) metadata.getSessionId() : null;

        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status("ACTIVE") // Default status
                .sessionId(sessionId)
                .build();
        if (metadata != null) {
            TokenMetadataEntity metadataEntity = TokenMetadataEntity.builder()
                    .token(token)
                    .deviceId(metadata != null ? metadata.getDeviceId() : null)
                    .device(metadata != null ? metadata.getDevice() : null)
                    .browser(metadata != null ? metadata.getBrowser() : null)
                    .os(metadata != null ? metadata.getOs() : null)
                    .ipAddress(metadata != null ? metadata.getIpAddress() : null)
                    .country(metadata != null ? metadata.getCountry() : null)
                    .city(metadata != null ? metadata.getCity() : null)
                    .sessionId(sessionId)
                    .userAgentRaw(metadata != null ? metadata.getUserAgentRaw() : null)
                    .loginMethod(metadata != null ? metadata.getLoginMethod() : null)
                    .mfaUsed(metadata != null && Boolean.TRUE.equals(metadata.getMfaUsed()))
                    .mfaType(metadata != null ? metadata.getMfaType() : null)
                    .isNewDevice(metadata != null && Boolean.TRUE.equals(metadata.getIsNewDevice()))
                    .isVpnOrProxy(metadata != null && Boolean.TRUE.equals(metadata.getIsVpnOrProxy()))
                    .networkProvider(metadata != null ? metadata.getNetworkProvider() : null)
                    .createdAt(Instant.now())
                    .issuer(null)
                    .clientId(null)
                    .riskScore(null)
                    .success(true)
                    .failureReason(null)
                    .latitude(null)
                    .longitude(null)
                    .timezone(null)
                    .logoutAt(null)
                    .revokedReason(null)
                    .build();
            token.setMetadata(metadataEntity);
        }
        tokenRepo.save(token);
    }

    // -------------------------------
    // Save Token (with status + metadata)
    // -------------------------------
    @Override
    public void saveUserTokenWithMetadata(
            UserEntity user,
            String jwtToken,
            TokenType type,
            Instant expiresAt,
            String status,
            TokenMetadata metadata
    ) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status(status != null ? status : "PENDING")
                .sessionId(metadata != null ? metadata.getSessionId() : null)
                .build();

        if (metadata != null) {
            TokenMetadataEntity metadataEntity = TokenMetadataEntity.builder()
                    .token(token)
                    .deviceId(metadata.getDeviceId())
                    .device(metadata.getDevice())
                    .browser(metadata.getBrowser())
                    .os(metadata.getOs())
                    .ipAddress(metadata.getIpAddress())
                    .country(metadata.getCountry())
                    .city(metadata.getCity())
                    .sessionId(metadata.getSessionId())
                    .userAgentRaw(metadata.getUserAgentRaw())
                    .loginMethod(metadata.getLoginMethod())
                    .mfaUsed(Boolean.TRUE.equals(metadata.getMfaUsed()))
                    .createdAt(Instant.now())
                    .build();
            token.setMetadata(metadataEntity);
        }
        // Persist both
        // Cascade takes care of metadata
        tokenRepo.save(token);
    }

    // -------------------------------
    // Revoke Tokens
    // -------------------------------
    @Override
    public  void revokeAllUserTokens(UserEntity user) {
        List<TokenEntity> validToken = tokenRepo.findAllValidTokensByUser(user.getId());
        validToken.forEach(token -> token.setRevoked(true));
        tokenRepo.saveAll(validToken);
    }

    // --- Revoke all tokens for a user except a session ---
    @Override
    public void revokeAllExceptSession(UserEntity user, String keepSessionId) {
        List<TokenEntity> tokens = tokenRepo.findAllValidTokensByUser(user.getId());
        tokens.stream()
                .filter(t -> !Objects.equals(t.getSessionId(), keepSessionId))
                .forEach(t -> t.setRevoked(true));
        tokenRepo.saveAll(tokens);
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
        userRepo.findByUsername(username).ifPresent(user -> {
            revokeAllUserTokens(user);
            user.setSession(null);
            userRepo.save(user);
        });

        // Notify via SSE
        ForceLogoutController.sendLogoutEventToAllSession(username);
    }

    // --- Revoke all tokens in a session ---
    @Override
    public void revokeTokensBySession(UserEntity user, String sessionId) {
        List<TokenEntity> tokens = tokenRepo.findAllByUserAndSessionId(user, sessionId);
        tokens.forEach(t -> t.setRevoked(true));
        tokenRepo.saveAll(tokens);
    }

    // Check if session is still valid
    public boolean isSessionActive(UserEntity user, String sessionId) {
        return tokenRepo.findAllByUserAndSessionId(user, sessionId).size() > 0;
    }
}
