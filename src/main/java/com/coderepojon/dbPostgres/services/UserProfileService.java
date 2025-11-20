package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.repositories.UserProfileRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

public interface UserProfileService {

    UserProfileEntity create(UserProfileEntity userProfile);

    List<UserProfileEntity> findAll();

    Optional<UserProfileEntity> findById(Long id);

    boolean existsById(Long id);

    UserProfileEntity update(Long id, UserProfileEntity userProfile);

    UserProfileEntity partialUpdate(Long id, UserProfileEntity userProfile);

    void delete(Long id);
}
