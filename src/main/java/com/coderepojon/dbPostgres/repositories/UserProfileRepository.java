package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserProfileRepository extends JpaRepository<UserProfileEntity, Long> {

    // Check if a profile already exists for a given user ID
    boolean existsByUser_Id(Long userId);

    // Fetch profile by user ID (for services or controllers)
    Optional<UserProfileEntity> findByUser_Id(Long userId);

    List<UserProfileEntity> findByUserIdIn(List<Long> userIds);
}
