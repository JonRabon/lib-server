package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<TokenEntity, Long> {
    // Find all non-revoked and non-expired tokens for a specific user
    @Query("""
        SELECT t FROM TokenEntity t
        WHERE t.user.id = :userId
          AND t.revoked = false
          AND t.expiresAt > CURRENT_TIMESTAMP
    """)
    List<TokenEntity> findAllValidTokensByUser(@Param("userId") Long userId);

    Optional<TokenEntity> findByToken(String token);

    Optional<TokenEntity> findByTokenAndUser(String token, UserEntity user);

    List<TokenEntity> findAllByUserAndSessionId(UserEntity user, String sessionId);
}
