package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;

import java.time.Instant;

public interface TokenService {
    void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt);
    void revokeAllUserTokens(UserEntity user);
    boolean isTokenRevoked(String token);
    void revokeToken(String token);
}
