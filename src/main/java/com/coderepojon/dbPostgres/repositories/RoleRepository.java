package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    RoleEntity findByName(String name);
}
