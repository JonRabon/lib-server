package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenMetadataEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenMetadataRepository extends JpaRepository<TokenMetadataEntity, Long> {

    //Find prior metadata for user by deviceId (to determine if device seen before
    @Query("SELECT m FROM TokenMetadataEntity m WHERE m.deviceId = :deviceId AND m.token.user.id = :userId")
    List<TokenMetadataEntity> findAllByDeviceIdAndUserId(@Param("deviceId") String deviceId, @Param("userId") Long userId);

    // Find metadata by token
    Optional<TokenMetadataEntity> findByToken(TokenEntity token);
}
