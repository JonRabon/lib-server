package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.mappers.Mapper;
import com.coderepojon.dbPostgres.services.UserProfileService;
import com.coderepojon.dbPostgres.services.impl.UserAccountServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user-profiles")
@RequiredArgsConstructor
public class UserProfileController {

    private final UserProfileService service;
    private final Mapper<UserProfileEntity, UserProfileDto> userProfileDtoMapper;
    private final UserAccountServiceImpl accountService;

    // Get all user profiles
    @GetMapping
    public ResponseEntity<List<UserProfileDto>> list() {
        List<UserProfileDto> profiles = service.findAll()
                .stream()
                .map(userProfileDtoMapper::mapTo)
                .collect(Collectors.toList());
        return ResponseEntity.ok(profiles);
    }

    // Get single user profile by ID
    @GetMapping("/{id}")
    public ResponseEntity<UserProfileDto> get(@PathVariable Long id) {
        return service.findById(id)
                .map(userProfileDtoMapper::mapTo)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Create new user profile
    @PostMapping("/add-user")
    public ResponseEntity<UserProfileDto> createUser(@RequestBody @Valid CreateUserRequestDto dto) {
        UserProfileDto created = accountService.createUser(dto);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
//        UserProfileEntity entity = userProfileDtoMapper.mapFrom(dto); // DTO -> Entity
//        UserProfileEntity saved = service.create(entity);
//        return new ResponseEntity<>(userProfileDtoMapper.mapTo(saved), HttpStatus.CREATED);
    }

    // Update existing user profile fully (PUT)
    @PutMapping("/{id}")
    public ResponseEntity<UserProfileDto> update(@PathVariable Long id, @RequestBody @Valid UserProfileDto dto) {
        UserProfileEntity entity = userProfileDtoMapper.mapFrom(dto);
        UserProfileEntity updated = service.update(id, entity);
        return ResponseEntity.ok(userProfileDtoMapper.mapTo(updated));
    }

    // Partial update of user profile (PATCH)
    @PatchMapping("/{id}")
    public ResponseEntity<UserProfileDto> partialUpdate(@PathVariable Long id, @RequestBody UserProfileDto dto) {
        UserProfileEntity entity = userProfileDtoMapper.mapFrom(dto);
        UserProfileEntity updated = service.partialUpdate(id, entity);
        return ResponseEntity.ok(userProfileDtoMapper.mapTo(updated));
    }

    // Delete a user profile
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
