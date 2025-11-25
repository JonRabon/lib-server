package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.mappers.Mapper;
import com.coderepojon.dbPostgres.repositories.UserProfileRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.services.UserAccountService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Transactional
public class UserAccountServiceImpl implements UserAccountService {

    private final UserRepository userRepository;
    private final UserProfileRepository profileRepository;
    private final PasswordEncoder passwordEncoder;
    private final Mapper<UserProfileEntity, UserProfileDto> userProfileDtoMapper;

    @Override
    public UserProfileDto createUser(CreateUserRequestDto req, MultipartFile avatar) {

        // --- 1. Generate & hash default password ---
        String defaultPassword = generateDefaultPassword(req);
        String hashedPassword = passwordEncoder.encode(defaultPassword);

        // --- 2. Create UserEntity ---
        UserEntity user = new UserEntity();
        user.setUsername(req.getEmail());
        user.setPassword(hashedPassword);
        userRepository.save(user);

        // --- 3. Create UserProfile ---
        UserProfileEntity profile = new UserProfileEntity();
        profile.setUser(user);
        profile.setEmail(req.getEmail());
        profile.setFirstName(req.getFirstName());
        profile.setMiddleName(req.getMiddleName());
        profile.setLastName(req.getLastName());
        profile.setBirthdate(req.getBirthdate());
        profile.setGender(req.getGender());
        profile.setMaritalStatus(req.getMaritalStatus());
        profile.setNationality(req.getNationality());
        profile.setPhoneNumber(req.getPhoneNumber());
        profile.setAlternatePhoneNumber(req.getAlternatePhoneNumber());
        profile.setAddressLine1(req.getAddressLine1());
        profile.setAddressLine2(req.getAddressLine2());
        profile.setCity(req.getCity());
        profile.setState(req.getState());
        profile.setPostalCode(req.getPostalCode());
        profile.setCountry(req.getCountry());
        profile.setBio(req.getBio());
        profile.setCreatedAt(Instant.now());
        profile.setUpdatedAt(Instant.now());

        // ---- 4. Save avatar if uploaded ---
        if (avatar != null && !avatar.isEmpty()) {

            String ext = Objects.requireNonNull(avatar.getOriginalFilename())
                    .substring(avatar.getOriginalFilename().lastIndexOf('.'));

            String fileName = user.getId() + ext;
            Path avatarDir = Paths.get("uploads/avatars");

            try {
                Files.createDirectories(avatarDir);
                Path filePath = avatarDir.resolve(fileName);
                Files.write(filePath, avatar.getBytes());

                profile.setAvatarUrl("http://localhost:8080/static/avatars/" + fileName);

            } catch (IOException e) {
                throw new RuntimeException("Failed to store avatar", e);
            }
        }

        profileRepository.save(profile);

        // --- 4. Return DTO ---
        return userProfileDtoMapper.mapTo(profile);
    }

    private String generateDefaultPassword(CreateUserRequestDto req) {
        String initials =
                "" + req.getFirstName().charAt(0)
                + (req.getMiddleName() != null && !req.getMiddleName().isBlank()
                ? req.getMiddleName().charAt(0)
                        : "")
                        + req.getLastName().charAt(0);

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMddyyyy");
        String birth = req.getBirthdate().format(formatter);

        return initials.toUpperCase() + birth;
    }
}
