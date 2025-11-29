package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.mappers.EntityMapper;
import com.coderepojon.dbPostgres.services.UserProfileService;
import com.coderepojon.dbPostgres.services.impl.UserAccountServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user-profiles")
@RequiredArgsConstructor
public class UserProfileController {

    private final UserProfileService service;
    private final EntityMapper<UserProfileEntity, UserProfileDto> userProfileDtoEntityMapper;
    private final UserAccountServiceImpl accountService;

    // Get all user profiles
    @GetMapping
    public ResponseEntity<List<UserProfileDto>> list() {
        List<UserProfileDto> profiles = service.findAll()
                .stream()
                .map(userProfileDtoEntityMapper::mapTo)
                .collect(Collectors.toList());
        return ResponseEntity.ok(profiles);
    }

    // Get single user profile by ID
    @GetMapping("/{id}")
    public ResponseEntity<UserProfileDto> get(@PathVariable Long id) {
        return service.findById(id)
                .map(userProfileDtoEntityMapper::mapTo)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Update existing user profile fully (PUT)
    @PutMapping("/{id}")
    public ResponseEntity<UserProfileDto> update(
            @PathVariable Long id,
            @RequestBody @Valid UserProfileDto dto) {
        UserProfileEntity entity = userProfileDtoEntityMapper.mapFrom(dto);
        UserProfileEntity updated = service.update(id, entity);
        return ResponseEntity.ok(userProfileDtoEntityMapper.mapTo(updated));
    }

    // Partial update of user profile (PATCH)
    @PatchMapping("/{id}")
    public ResponseEntity<UserProfileDto> partialUpdate(@PathVariable Long id, @RequestBody UserProfileDto dto) {
        UserProfileEntity entity = userProfileDtoEntityMapper.mapFrom(dto);
        UserProfileEntity updated = service.partialUpdate(id, entity);
        return ResponseEntity.ok(userProfileDtoEntityMapper.mapTo(updated));
    }

    // Delete a user profile
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    // ---------- AVATAR ONLY (FILE UPLOAD) ----------
    // Update existing user profile fully (PUT)
    @PutMapping(value = "/{id}/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserProfileDto> updateAvatar(
            @PathVariable Long id,
            @RequestPart("avatar") MultipartFile avatar
    ) {
        UserProfileDto updated = service.updateAvatar(id, avatar);
        return ResponseEntity.ok(updated);
    }

    @PatchMapping(value = "/{id}/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserProfileDto> patchAvatar(
            @PathVariable Long id,
            @RequestPart("avatar") MultipartFile avatar
    ) {
        UserProfileDto updated = service.updateAvatar(id, avatar);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}/avatar")
    public ResponseEntity<Void> deleteAvatar(@PathVariable Long id) {
        service.deleteAvatar(id);
        return ResponseEntity.noContent().build();
    }

}
