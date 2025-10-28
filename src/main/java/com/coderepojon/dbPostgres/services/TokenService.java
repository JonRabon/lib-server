package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;

import java.time.Instant;
import java.util.Map;

public interface TokenService {

    boolean existAndValid(String token, UserEntity user);

    void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt);

    void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt, TokenMetadata metadata);

    void revokeAllUserTokens(UserEntity user);

    void revokeAllExceptSession(UserEntity user, String sessionId);

    boolean isTokenRevoked(String token);

    void revokeToken(String token);

    // Allow admin to revoke tokens by username
    void revokeTokensByUsername(String username);

    void revokeTokensBySession(UserEntity user, String sessionId);

    /**
     * Saves a JWT token along with detailed metadata such as device, browser, and location info.
     * Typically used during login or token refresh.
     */
    void saveUserTokenWithMetadata(
            UserEntity user,
            String jwtToken,
            TokenType type,
            Instant expiresAt,
            String status,
            TokenMetadata metadata
    );
}
