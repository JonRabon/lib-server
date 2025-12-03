package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.mappers.EntityMapper;
import com.coderepojon.dbPostgres.repositories.UserProfileRepository;
import com.coderepojon.dbPostgres.services.UserProfileService;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class UserProfileServiceImpl implements UserProfileService {

    private final UserProfileRepository userProfileRepository;
    private final EntityMapper<UserProfileEntity, UserProfileDto> userProfileDtoEntityMapper;

    private final Path avatarDir = Paths.get("uploads/avatars");

    @Override
    public UserProfileEntity create(UserProfileEntity userProfile) {

        if (userProfileRepository.existsByUser_Id(userProfile.getUser().getId())) {
            throw new IllegalArgumentException("User already has a profile");
        }

        userProfile.setCreatedAt(Instant.now());
        userProfile.setUpdatedAt(Instant.now());
        return userProfileRepository.save(userProfile);
    }

    @Override
    @Transactional
    public List<UserProfileEntity> findAll() {
        return userProfileRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserProfileEntity> findById(Long id) {
        return userProfileRepository.findById(id);
    }

    @Override
    public boolean existsById(Long id) {
        return userProfileRepository.existsById(id);
    }

    @Override
    public UserProfileEntity update(Long id, UserProfileEntity userProfile) {
        UserProfileEntity existing = userProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("UserProfile not found"));

        userProfile.setId(existing.getId());
        userProfile.setUser(existing.getUser()); // user cannot change
        userProfile.setCreatedAt(existing.getCreatedAt());
        userProfile.setUpdatedAt(Instant.now());

        return userProfileRepository.save(userProfile);
    }

    @Override
    public UserProfileEntity partialUpdate(Long id, UserProfileEntity userProfile) {
        return userProfileRepository.findById(id)
                .map(existing -> {
                    Optional.ofNullable(userProfile.getEmail()).ifPresent(existing::setEmail);
                    Optional.ofNullable(userProfile.getFirstName()).ifPresent(existing::setFirstName);
                    Optional.ofNullable(userProfile.getMiddleName()).ifPresent(existing::setMiddleName);
                    Optional.ofNullable(userProfile.getLastName()).ifPresent(existing::setLastName);
                    Optional.ofNullable(userProfile.getBirthdate()).ifPresent(existing::setBirthdate);
                    Optional.ofNullable(userProfile.getGender()).ifPresent(existing::setGender);
                    Optional.ofNullable(userProfile.getMaritalStatus()).ifPresent(existing::setMaritalStatus);
                    Optional.ofNullable(userProfile.getPhoneNumber()).ifPresent(existing::setPhoneNumber);
                    Optional.ofNullable(userProfile.getAlternatePhoneNumber()).ifPresent(existing::setAlternatePhoneNumber);
                    Optional.ofNullable(userProfile.getAddressLine1()).ifPresent(existing::setAddressLine1);
                    Optional.ofNullable(userProfile.getAddressLine2()).ifPresent(existing::setAddressLine2);
                    Optional.ofNullable(userProfile.getCity()).ifPresent(existing::setCity);
                    Optional.ofNullable(userProfile.getState()).ifPresent(existing::setState);
                    Optional.ofNullable(userProfile.getPostalCode()).ifPresent(existing::setPostalCode);
                    Optional.ofNullable(userProfile.getCountry()).ifPresent(existing::setCountry);
                    Optional.ofNullable(userProfile.getBio()).ifPresent(existing::setBio);
                    Optional.ofNullable(userProfile.getNationality()).ifPresent(existing::setNationality);

                    existing.setUpdatedAt(Instant.now());
                    return userProfileRepository.save(existing);
                })
                .orElseThrow(() -> new RuntimeException("UserProfile not found"));
    }

    @Override
    public UserProfileDto updateAvatar(Long id, MultipartFile avatar){
        if (avatar == null || avatar.isEmpty()) {
            throw new RuntimeException("Avatar file is required");
        }

        UserProfileEntity profile = userProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("UserProfile not found"));

        // Ensure dir exists
        try{
            Files.createDirectories(avatarDir);
        } catch (IOException e) {
            throw new RuntimeException("Could not create avatar directory", e);
        }

        // Extract extension
        String ext = Objects.requireNonNull(avatar.getOriginalFilename())
                .substring(avatar.getOriginalFilename().lastIndexOf('.'));

        String fileName = profile.getUser().getId() + ext;
        Path path = avatarDir.resolve(fileName);

        //Delete old avatar if exists
        deleteAvatarFileIfExists(profile.getAvatarUrl());

        try {
            Files.write(path, avatar.getBytes());
        } catch (IOException e) {
            throw new RuntimeException("Failed to save avatar", e);
        }

        profile.setAvatarUrl("http://localhost:8080/static/avatars/" + fileName);
        profile.setUpdatedAt(Instant.now());
        userProfileRepository.save(profile);

        return userProfileDtoEntityMapper.mapTo(profile);
    }

    @Override
    public void deleteAvatar(Long id) {
        UserProfileEntity profile = userProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("UserProfile not found"));

        deleteAvatarFileIfExists(profile.getAvatarUrl());

        profile.setAvatarUrl(null);
        profile.setUpdatedAt(Instant.now());
        userProfileRepository.save(profile);
    }

    @Override
    public void delete(Long id) {
        UserProfileEntity profile = userProfileRepository.findById(id)
                        .orElseThrow(() -> new NoSuchElementException("Profile not found"));

        userProfileRepository.deleteById(id); // cascades delete user
    }

    private void deleteAvatarFileIfExists(String avatarUrl) {
        if (avatarUrl == null) return;

        String filename =avatarUrl.substring(avatarUrl.lastIndexOf('/') + 1);
        Path path = avatarDir.resolve(filename);

        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {}
    }
}
