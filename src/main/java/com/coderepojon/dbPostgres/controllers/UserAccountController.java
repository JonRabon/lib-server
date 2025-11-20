package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.services.UserAccountService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserAccountController {

    private final UserAccountService accountService;

    @PostMapping
    public ResponseEntity<UserProfileDto> createUser(@RequestBody @Valid CreateUserRequestDto requestDto) {
        UserProfileDto created = accountService.createUser(requestDto);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }
}
