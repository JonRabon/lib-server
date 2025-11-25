package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.services.UserAccountService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
}
