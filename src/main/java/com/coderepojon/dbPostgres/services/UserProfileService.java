package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.repositories.UserProfileRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface UserProfileService {

    UserProfileEntity create(UserProfileEntity userProfile);

    List<UserProfileEntity> findAll();

    Optional<UserProfileEntity> findById(Long id);

    boolean existsById(Long id);

    UserProfileEntity update(Long id, UserProfileEntity userProfile);

    UserProfileEntity partialUpdate(Long id, UserProfileEntity userProfile);

    UserProfileDto updateAvatar(Long id, MultipartFile avatar);

    void deleteAvatar(Long id);

    void delete(Long id);
}
