package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    // Simple lookup by username
    Optional<UserEntity> findByUsername(String username);

    @Query("SELECT u FROM UserEntity u JOIN FETCH u.roles WHERE u.username = :username")
    Optional<UserEntity> fetchUserWithRoles(@Param("username") String username);
}
