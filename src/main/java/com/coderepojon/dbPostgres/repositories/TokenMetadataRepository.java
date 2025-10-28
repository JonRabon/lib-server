package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.TokenMetadataEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenMetadataRepository extends JpaRepository<TokenMetadataEntity, Long> {
}
