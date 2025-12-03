package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.BulkStatusUpdateDto;
import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.services.UserAccountService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserAccountController {

    private final UserAccountService accountService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserProfileDto> createUser(
            @RequestPart("userData") @Valid CreateUserRequestDto requestDto,
            @RequestPart(value = "avatar", required = false) MultipartFile avatar
    ) {
        UserProfileDto created = accountService.createUser(requestDto, avatar);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @PatchMapping("/bulk-status")
    public ResponseEntity<List<UserProfileDto>> updateStatusMultiple(
            @RequestBody @Valid BulkStatusUpdateDto request) {

        List<UserProfileDto> updatedProfiles = accountService
                .updateStatusMultiple(request.getIds(), request.getStatus());

        return ResponseEntity.ok(updatedProfiles);
    }

    // New single-user endpoint
    @PatchMapping("/{userId}/status")
    public ResponseEntity<UserProfileDto> updateUser(
            @PathVariable Long userId,
            @RequestBody @Valid UserDto request
    ) {
        return ResponseEntity.ok(
                accountService.updateUser(userId, request)
        );
    }
}
