package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserAccountService {

    UserProfileDto createUser(CreateUserRequestDto request, MultipartFile avatar);

    List<UserProfileDto> updateStatusMultiple(List<Long> userIds, String status);

    UserProfileDto updateUser(Long userId, UserDto request);

}
