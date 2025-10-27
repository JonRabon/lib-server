package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;

import java.time.Instant;
import java.util.Map;

public interface TokenService {
    boolean existAndValid(String token, UserEntity user);

    void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt);

    void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt, Map<String, Object> metadata);
    void revokeAllUserTokens(UserEntity user);
    boolean isTokenRevoked(String token);
    void revokeToken(String token);

    // Allow admin to revoke tokens by username
    void revokeTokensByUsername(String username);
    void saveUserTokenWithMetadata(
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
    );
}
