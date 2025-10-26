package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.services.TokenService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepo;

    public  TokenServiceImpl(TokenRepository tokenRepo) {
        this.tokenRepo = tokenRepo;
    }

    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .build();

        tokenRepo.save(token);
    }

    @Override
    public  void revokeAllUserTokens(UserEntity user) {
        List<TokenEntity> validTokens = tokenRepo.findAllByUserAndRevokedFalse(user);
        validTokens.forEach(t -> t.setRevoked(true));
        tokenRepo.saveAll(validTokens);
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
}
